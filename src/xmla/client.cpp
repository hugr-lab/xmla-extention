#include "xmla/client.hpp"

#include "xmla/auth.hpp"
#include "xmla/dime.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla/sealing.hpp"

#include <algorithm>

namespace xmla {

namespace {

//! Fault text that means "you are known but not permitted", as opposed to "the
//! request was bad". Keeps AuthorizationError distinct from ServerError.
const char *const kDeniedMarkers[] = {"does not have access", "permission", "not authorized", "access is denied"};

std::string ToLower(const std::string &in) {
	std::string out = in;
	std::transform(out.begin(), out.end(), out.begin(),
				   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
	return out;
}

//! Cheap shape check on an unsealed response, before it is parsed.
//!
//! Deliberately not a parse: a SOAP fault is also a valid envelope and is
//! handled a step earlier, so this only has to separate "an XML document from
//! the server" from "plaintext that did not decrypt".
bool LooksLikeXmla(const std::string &text) {
	size_t i = 0;
	// Skip a BOM the sealing layer did not strip, plus leading whitespace.
	if (text.size() >= 3 && static_cast<uint8_t>(text[0]) == 0xEF && static_cast<uint8_t>(text[1]) == 0xBB &&
		static_cast<uint8_t>(text[2]) == 0xBF) {
		i = 3;
	}
	while (i < text.size() && isspace(static_cast<unsigned char>(text[i]))) {
		i++;
	}
	return i < text.size() && text[i] == '<';
}

}  // namespace

void ConnectionTarget::Validate() const {
	if (host.empty()) {
		throw ConnectionError("host is required");
	}
	if (port == 0) {
		// There is no default. See research D9: the named-instance redirector has
		// no public specification, so the port must be pinned, and guessing one
		// presents as a hang.
		throw ConnectionError("port is required and must be pinned; there is no default and no redirector");
	}
	if (timeout_seconds <= 0) {
		throw ConnectionError("timeout must be positive; unbounded waits are not offered");
	}
}

Session::~Session() {
	Close();
}

void Session::Open(std::shared_ptr<Channel> channel, std::unique_ptr<GssContext> context) {
	target_.Validate();
	if (!context) {
		throw AuthenticationError("no security context was supplied");
	}

	// Reset everything scoped to a CONNECTION, not to the Session object. A
	// reconnect that kept these would send its first record with OPT_NEGO
	// already set and a SessionId from the dead connection - and wrong
	// negotiation bits are SILENTLY FATAL: the server closes the connection with
	// no error and logs nothing.
	//
	// Close FIRST. Overwriting the stream leaks the socket for the life of the
	// process and leaves the server-side session open too - in exactly the
	// reconnect path this reset exists to support.
	if (stream_) {
		Close();
	}
	first_record_ = true;
	session_id_.clear();
	context_.reset();
	seal_.reset();
	terms_ = NegotiatedTerms();
	scrub_ = Scrubber(target_.host, credential_.principal);

	try {
		std::shared_ptr<Channel> chan = channel;
		if (!chan) {
			chan = std::make_shared<SocketChannel>(target_.host, target_.port, target_.timeout_seconds);
		}
		stream_.reset(new MessageStream(chan));
		state_ = State::NEGOTIATED;

		std::unique_ptr<GssContext> ctx = std::move(context);

		auth::Handshake(*ctx, [this](const std::string &token) { return SendAuthenticate(token); });

		// Everything after the handshake is sealed with this context. The server
		// enforces it: an unsealed message is dropped with no error and nothing
		// in its log. Building the provider HERE rather than at first use keeps a
		// context that cannot seal inside the FR-029 taxonomy, instead of
		// surfacing as something unclassified on the first request.
		seal_ = ctx->MakeSealProvider();
		context_ = std::move(ctx);
		terms_.protection = true;
		state_ = State::AUTHENTICATED;
	} catch (...) {
		state_ = State::FAILED;
		throw;
	}
}

void Session::Close() {
	if (stream_) {
		stream_->Close();
		stream_.reset();
	}
	seal_.reset();
	context_.reset();
	state_ = State::CLOSED;
}

std::string Session::SealDescription() const {
	return seal_ ? seal_->Describe() : std::string("none");
}

void Session::RequireAuthenticated() const {
	if (state_ != State::AUTHENTICATED) {
		throw AuthenticationError("the session is not authenticated");
	}
}

std::string Session::SendAuthenticate(const std::string &token_b64) {
	// NEGO stays clear on the very first record and is set on every later one.
	const Bytes options = first_record_ ? dime::OptionsClearText() : dime::OptionsNegotiated();
	first_record_ = false;

	// The handshake is sent UNSEALED - there is no context to seal with yet - but
	// it still carries the BOM the reference client writes ahead of every body.
	const std::string envelope = envelopes::Authenticate(token_b64);
	Bytes payload(sealing::BOM, sealing::BOM + sealing::BOM_LEN);
	payload.insert(payload.end(), envelope.begin(), envelope.end());
	stream_->SendMessage(payload, options);

	const Bytes raw = stream_->ReceiveMessage();
	const std::string text(raw.begin(), raw.end());
	// Every authenticate response is fault-checked, INCLUDING the terminal one.
	// For NTLM the client context completes as it emits its last token, so the
	// handshake loop returns without looking at the reply - a "Logon failure"
	// there would otherwise be dropped, the session would reach AUTHENTICATED,
	// and the error would resurface mis-attributed to whatever ran next.
	RaiseForFault(text, /*during_authentication=*/true);
	return text;
}

Rowset Session::RoundtripRowset(const std::string &payload) {
	const Bytes body(payload.begin(), payload.end());
	stream_->SendMessage(sealing::SealMessage(*seal_, body), dime::OptionsNegotiated());

	const Bytes raw = stream_->ReceiveMessage();
	const Bytes plain = sealing::UnsealMessage(*seal_, raw);
	const std::string text(plain.begin(), plain.end());

	CaptureSessionId(text);
	RaiseForFault(text, /*during_authentication=*/false);

	// An empty rowset is a MEANINGFUL answer - "no catalogs visible to this
	// account" is distinct from "refused" - so a response that is not XML at all
	// must not arrive looking like one. The likeliest failure of a cipher layer
	// (wrong context, desynchronised sequence, a mechanism whose framing differs)
	// produces exactly that indistinguishable emptiness.
	if (!LooksLikeXmla(text)) {
		throw ProtocolError(
			"the unsealed response is not an XMLA envelope; the security "
			"context or the frame layout is wrong");
	}
	return ParseRowset(text);
}

void Session::CaptureSessionId(const std::string &text) {
	if (!session_id_.empty()) {
		return;
	}
	std::string found;
	// [MS-SSAS] "Initialization for Non-HTTP Transport": every request after the
	// first MUST carry the SessionId the server returns to BeginSession. Without
	// this the client re-sends BeginSession forever and opens a new server-side
	// session per request.
	if (FindAttribute(text, "Session", "SessionId", found) && !found.empty()) {
		session_id_ = found;
	}
}

void Session::RaiseForFault(const std::string &text, bool during_authentication) const {
	const Fault fault = FindFault(text);
	if (!fault.present) {
		return;
	}
	std::string detail = scrub_(fault.message.empty() ? fault.code : fault.message);
	if (detail.size() > 300) {
		detail.resize(300);
	}
	const std::string lowered = ToLower(fault.message);
	for (const char *marker : kDeniedMarkers) {
		if (lowered.find(marker) != std::string::npos) {
			throw AuthorizationError("the account was refused access", detail);
		}
	}
	if (during_authentication) {
		// A fault during the handshake is an identity problem, not a bad request
		// - keeping it in the right category is the point of having categories.
		throw AuthenticationError("authentication was refused", detail);
	}
	throw ServerError("the server rejected the request", detail);
}

Rowset Session::Discover(const std::string &request_type, const std::map<std::string, std::string> &restrictions,
						 const std::string &catalog) {
	RequireAuthenticated();
	return RoundtripRowset(envelopes::Discover(request_type, restrictions, catalog, session_id_));
}

Rowset Session::Execute(const std::string &statement, const std::string &catalog) {
	RequireAuthenticated();
	return RoundtripRowset(envelopes::Execute(statement, catalog, session_id_));
}

}  // namespace xmla
