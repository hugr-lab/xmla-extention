//===----------------------------------------------------------------------===//
// Session assembly: negotiate -> authenticate -> request.
//
// Turns server responses into the categorised errors of FR-029 so a caller can
// act on the category without parsing message text.
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/gss_context.hpp"
#include "xmla/redact.hpp"
#include "xmla/rowset.hpp"
#include "xmla/seal_provider.hpp"
#include "xmla/transport.hpp"

#include <map>
#include <memory>
#include <string>

namespace xmla {

static const double DEFAULT_TIMEOUT_SECONDS = 30.0;

//! Where to connect. NO DEFAULT PORT: a default invites guessing between a
//! default instance's well-known port and a named instance's pinned one, and
//! guessing wrong presents as a hang rather than as an error.
struct ConnectionTarget {
	std::string host;
	uint16_t port = 0;
	double timeout_seconds = DEFAULT_TIMEOUT_SECONDS;

	void Validate() const;
};

//! Settled once per session and immutable thereafter.
struct NegotiatedTerms {
	std::string content_type = "text/xml";
	bool request_binary = false;
	bool response_binary = false;
	bool request_compressed = false;
	bool response_compressed = false;
	bool protection = false;
};

enum class State { UNCONNECTED, NEGOTIATED, AUTHENTICATED, CLOSED, FAILED };

//! An authenticated conversation with an instance.
class Session {
public:
	Session(ConnectionTarget target, Credential credential)
		: target_(std::move(target)), credential_(std::move(credential)) {}
	~Session();

	//! Connect, negotiate and authenticate. A returned session is usable.
	//!
	//! The security context is REQUIRED and is built by the caller. That looks
	//! like an inconvenience and is the layering: constructing one here would
	//! make this file - and with it the whole protocol library - depend on
	//! GSSAPI, which is what constitution III's hermetic suite cannot afford. A
	//! caller with GSSAPI linked writes:
	//!
	//!     auto ctx = GssContext::Create(credential, host, port, password);
	//!     session.Open(nullptr, std::move(ctx));
	//!
	//! `channel` is the test seam: null opens a real socket.
	void Open(std::shared_ptr<Channel> channel, std::unique_ptr<GssContext> context);

	//! Idempotent. Closing an already-failed session is not an error.
	void Close();

	Rowset Discover(const std::string &request_type, const std::map<std::string, std::string> &restrictions = {},
					const std::string &catalog = std::string());

	//! Run a read-only analytic statement.
	//!
	//! Read-only by VALIDATION, not by construction. XMLA's <Statement> is the
	//! entry point to the whole command surface — MDX writeback, DMX and
	//! stored-procedure CALL all travel through it — so the statement is checked
	//! against an allowlist of query keywords and refused otherwise.
	//!
	//! Throws ProtocolError when the statement is not a query, which includes a
	//! statement batch: a separator with further text after it is refused even
	//! when the first keyword is a query keyword.
	//!
	//! The guard is not sufficient on its own. Grant the connecting account
	//! read-only permissions on the server.
	Rowset Execute(const std::string &statement, const std::string &catalog = std::string());

	State state() const {
		return state_;
	}
	const NegotiatedTerms &terms() const {
		return terms_;
	}
	//! For diagnostics. Never contains a principal, realm or token.
	std::string SealDescription() const;

private:
	void RequireAuthenticated() const;
	std::string SendAuthenticate(const std::string &token_b64);
	Rowset RoundtripRowset(const std::string &payload);
	void CaptureSessionId(const std::string &text);
	void RaiseForFault(const std::string &text, bool during_authentication) const;

	ConnectionTarget target_;
	Credential credential_;
	NegotiatedTerms terms_;
	State state_ = State::UNCONNECTED;

	std::unique_ptr<MessageStream> stream_;
	std::unique_ptr<GssContext> context_;
	std::unique_ptr<SealProvider> seal_;
	Scrubber scrub_;
	std::string session_id_;
	bool first_record_ = true;
};

}  // namespace xmla
