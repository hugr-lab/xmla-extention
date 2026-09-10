#include "xmla/client.hpp"

#include "xmla/auth.hpp"
#include "xmla/dime.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla/sealing.hpp"

#include <algorithm>

namespace xmla {

namespace {

//! Said in ONE place, because both read paths raise it and they must not drift.
const char *const kCellsetMessage =
	"the server returned a multidimensional cellset rather than a rowset; "
	"this client reads rows and asked for Format=Tabular";

//! Fault text that means "you are known but not permitted", as opposed to "the
//! request was bad". Keeps AuthorizationError distinct from ServerError.
const char *const kDeniedMarkers[] = {"does not have access", "permission", "not authorized", "access is denied"};

//! ASCII-only. ::tolower follows LC_CTYPE, and this fold decides an ERROR
//! CATEGORY: the result is matched against kDeniedMarkers to tell "you are known
//! but not permitted" from "the request was bad". Under tr_TR.UTF-8 a fault
//! containing "Permission" or "Not Authorized" would not fold to the marker, and
//! an AuthorizationError would be reported as a ServerError — sending the
//! operator to check the request instead of the account's permissions.
std::string ToLower(const std::string &in) {
	std::string out = in;
	std::transform(out.begin(), out.end(), out.begin(),
				   [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; });
	return out;
}

//! Cheap shape check on an unsealed response, before it is parsed.
//!
//! Deliberately not a parse: a SOAP fault is also a valid envelope and is
//! handled a step earlier, so this only has to separate "an XML document from
//! the server" from "plaintext that did not decrypt".
//! Whether a response is a multidimensional cellset rather than a rowset.
//!
//! Detected by the cellset's own ELEMENTS, not by the string "mddataset" —
//! that is the namespace URI on <root>, so matching it as an element name finds
//! nothing. The XMLA MDDataSet schema puts OlapInfo, Axes and CellData under
//! that root; Axes and CellData are the two that cannot plausibly appear in a
//! rowset. HasElement, not FindElementText: FindElementText wants an element's
//! TEXT and so skips self-closing tags, and a cellset whose cells are all null
//! has an empty CellData that a serializer may write as <CellData/>.
bool LooksLikeCellset(const std::string &text) {
	return HasElement(text, "CellData") || HasElement(text, "Axes");
}

bool LooksLikeXmla(const std::string &text) {
	size_t i = 0;
	// Skip a BOM the sealing layer did not strip, plus leading whitespace.
	if (text.size() >= 3 && static_cast<uint8_t>(text[0]) == 0xEF && static_cast<uint8_t>(text[1]) == 0xBB &&
		static_cast<uint8_t>(text[2]) == 0xBF) {
		i = 3;
	}
	// XML leading whitespace is exactly these four (XML 1.0 §2.3); isspace()
	// follows LC_CTYPE and in some locales accepts more.
	while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) {
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

	Rowset rows = ParseRowset(text);

	// A cellset is not a rowset, and must not arrive looking like an empty one.
	//
	// Execute asks for Format=Tabular precisely so that an MDX query comes back
	// as rows. Before it did, the server returned an <mddataset> — axes and
	// cells — this scanner found no <row> in it, and every MDX query reported
	// ZERO ROWS with no error. An empty rowset is a meaningful answer here, so
	// there was nothing to distinguish "the cube is empty" from "the client
	// cannot read this shape". If a server ever ignores the property, this says
	// so instead.
	if (rows.empty() && LooksLikeCellset(text)) {
		throw ProtocolError(kCellsetMessage);
	}
	return rows;
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

void Session::SendRequest(const std::string &payload) {
	const Bytes body(payload.begin(), payload.end());
	stream_->SendMessage(sealing::SealMessage(*seal_, body), dime::OptionsNegotiated());
}

std::unique_ptr<RowCursor> Session::ExecuteCursor(const std::string &statement, const std::string &catalog,
												  size_t parser_limit) {
	RequireAuthenticated();
	SendRequest(envelopes::Execute(statement, catalog, session_id_));
	// Not make_unique: the constructor is private and Session is its friend.
	return std::unique_ptr<RowCursor>(new RowCursor(*this, parser_limit));
}

RowCursor::RowCursor(Session &session, size_t parser_limit) : session_(session), parser_limit_(parser_limit) {
	unsealer_.reset(new sealing::Unsealer(*session.seal_));
}

RowCursor::~RowCursor() {
	if (complete_) {
		return;
	}
	// Abandoned early - which is the whole point of the class. The remaining
	// records are NOT read: reading them would transfer exactly the bytes this
	// exists to avoid. That leaves the socket mid-message, so the session is
	// marked failed and the connection is not reused.
	//
	// Guarded, because Session::Close() resets stream_ and Session's destructor
	// calls Close(): a cursor destroyed after its session was closed dereferenced
	// null. The scan gets the order right by member declaration order and by
	// resetting the cursor before closing, but both are load-bearing and
	// unenforced on what is now public protocol-layer API, so a mis-ordered
	// teardown degrades to a leaked response rather than a crash.
	if (session_.stream_) {
		session_.stream_->AbandonMessage();
		// FAILED only when there was something to abandon. A session already
		// closed is CLOSED, and overwriting that with FAILED would report a
		// fault where there was an orderly shutdown.
		session_.state_ = State::FAILED;
	}
}

const std::vector<std::string> &RowCursor::columns() const {
	return parser_.columns();
}

void RowCursor::CheckHead() {
	// Only while the response is still ARRIVING. An unconditional early return
	// here meant a response whose plaintext is empty — a zero-length reply, or
	// frames that unseal to nothing — reached complete_ with the guard never
	// having run: Next() reported drained and the scan produced zero rows with
	// no error. This layer documents an empty rowset as a MEANINGFUL answer, so
	// a framing or decrypt failure then presents as "the table is empty", which
	// is the indistinguishable emptiness the guard exists to prevent. The
	// whole-message path rejects the same bytes.
	if (head_.empty() && !complete_) {
		return;
	}
	// An empty rowset is a MEANINGFUL answer - "no rows visible to this account"
	// is distinct from "refused" - so a response that is not XML at all must not
	// arrive looking like one. The likeliest failure of a cipher layer (wrong
	// context, desynchronised sequence, a mechanism whose framing differs)
	// produces exactly that indistinguishable emptiness.
	//
	// One '<' is enough to settle it, and anything shorter than that is either
	// still arriving or not a document.
	if (!head_checked_) {
		if (!LooksLikeXmla(head_)) {
			throw ProtocolError(
				"the unsealed response is not an XMLA envelope; the security "
				"context or the frame layout is wrong");
		}
		head_checked_ = true;
	}
	// Both of these run on EVERY pump, not once, because the prefix grows: the
	// SOAP header carrying SessionId and the Fault that replaces the body need
	// not arrive in the same record. Both are cheap - CaptureSessionId returns
	// immediately once it has one, FindFault rejects on a substring - and the
	// prefix they scan is bounded.
	session_.CaptureSessionId(head_);
	// A SOAP Fault REPLACES the body, so it is in the prefix or it is not there.
	// A fault emitted after rows have already streamed is therefore not seen
	// here; the whole-message path (Discover, Execute) still inspects an entire
	// document, and that is the path the metadata requests use.
	session_.RaiseForFault(head_, /*during_authentication=*/false);
}

const size_t RowCursor::DEFAULT_PARSER_LIMIT;
const size_t RowCursor::HEAD_LIMIT;

void RowCursor::Feed(const Bytes &plain) {
	if (plain.empty()) {
		return;
	}
	const char *bytes = reinterpret_cast<const char *>(plain.data());
	parser_.Append(bytes, plain.size());
	if (head_.size() < HEAD_LIMIT) {
		// May overshoot by one frame, which is the point: the limit bounds the
		// prefix, it does not have to split a frame to hit it exactly.
		head_.append(bytes, plain.size());
	}
}

void RowCursor::Pump() {
	// The session must still be open. Close() resets BOTH stream_ and seal_, and
	// the unsealer holds a SealProvider REFERENCE — so pumping after a close was
	// a null dereference at best and a use-after-free at worst. The destructor
	// was guarded for this and the live path was not; which of the two a
	// mis-ordered caller hit depended on whether rows happened to be buffered.
	if (!session_.stream_ || !session_.seal_) {
		throw ConnectionError("the session was closed while the response was still being read");
	}
	// The cap that MessageStream's stopped being once records are consumed one
	// at a time. Checked HERE, before the read, rather than after appending a
	// record: entering Pump the parser has just compacted (the Next() that sent
	// us here did it), so this measures exactly what the parser retains. After
	// the append it measured "retained plus one whole record", which is not the
	// quantity the limit is chosen for.
	if (parser_.buffered() > parser_limit_) {
		throw ProtocolError("buffered " + std::to_string(parser_.buffered()) +
							" bytes of response without a complete row (limit " + std::to_string(parser_limit_) +
							"); the document is unterminated or the stream is desynchronised");
	}
	Bytes record;
	bool more = true;
	session_.stream_->ReceiveRecord(record, more);
	Feed(unsealer_->Append(record));
	if (!more) {
		unsealer_->Finish();
		Feed(unsealer_->Flush());
		parser_.Finish();
		complete_ = true;
	}
	CheckHead();
}

bool RowCursor::Next(std::vector<Cell> &out) {
	if (drained_) {
		return false;
	}
	for (;;) {
		if (parser_.Next(out)) {
			emitted_ = true;
			return true;
		}
		if (complete_) {
			// The parser has seen the whole document and has no further row —
			// which is where the SAME cellset check the whole-message path makes
			// belongs. Without it the two paths disagreed about one response:
			// RoundtripRowset threw and the cursor reported drained with zero
			// rows. The extension only drives the cursor with DAX today, but
			// ExecuteCursor is public protocol-layer API and RejectIfMutating
			// accepts SELECT, so MDX through it is a supported call — and it had
			// the pre-fix behaviour intact.
			//
			// The prefix suffices: a cellset's OlapInfo and Axes are at the
			// start of the document, well inside HEAD_LIMIT.
			if (!emitted_ && LooksLikeCellset(head_)) {
				throw ProtocolError(kCellsetMessage);
			}
			drained_ = true;
			return false;
		}
		Pump();
	}
}

}  // namespace xmla
