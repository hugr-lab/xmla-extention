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

#include "xmla/sealing.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

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

class Session;

//! A forward-only cursor over one response's rows, decoded as they arrive.
//!
//! The point is EARLY TERMINATION. `SELECT ... LIMIT 5` from a fact table cannot
//! be expressed as a DAX clause, because DuckDB v2.0 passes no limit to a table
//! function at all - TableFunctionInitInput carries the projection, the filters
//! and the sample options, and there is no field for a limit - so a scan cannot
//! know to ask for five rows. What it CAN do is stop reading. Destroying a cursor
//! before it is drained abandons the rest of the response instead of draining it,
//! so the bytes still on the server's side are never transferred.
//!
//! The cursor borrows its Session and must not outlive it. It leaves the session
//! unusable if abandoned part-way, deliberately: half a DIME message has been
//! read off the socket and there is no way back to a record boundary.
class RowCursor {
public:
	//! Ceiling on what the parser may hold without producing a row.
	//!
	//! MessageStream caps the bytes it buffers, but that cap became PER RECORD
	//! once records were consumed one at a time — so a peer streaming records
	//! that form no complete row grew the parser without limit. This is the
	//! missing cap. It is smaller than MessageStream's 64 MiB on purpose: an
	//! unterminated comment makes every feed re-search the pending region, so
	//! the work before the cap fires is on the order of the limit squared over
	//! the read size, and 16 MiB keeps that under a second where 64 MiB does
	//! not. A legitimate document never approaches it — the parser retains at
	//! most one row plus a partial tag, because compaction reclaims the rest.
	//!
	//! Overridable for the same reason MessageStream's is: a test that had to
	//! push 16 MiB through the fake provider to reach it would not be written.
	static const size_t DEFAULT_PARSER_LIMIT = 16 * 1024 * 1024;

	~RowCursor();
	RowCursor(const RowCursor &) = delete;
	RowCursor &operator=(const RowCursor &) = delete;

	//! Pull the next row. False means the response is exhausted.
	bool Next(std::vector<Cell> &out);

	//! The column union DISCOVERED SO FAR, which grows as rows arrive.
	//!
	//! A streaming caller therefore cannot resolve a name to an index once and
	//! be done: a column that is null in every row read so far is not in this
	//! list yet. Map cell.column through this list per row, extending the mapping
	//! when it grows - do not probe the first row for a schema. Probing the first
	//! row is exactly the bug that made a whole scan return NULL, twice.
	const std::vector<std::string> &columns() const;

	//! True once the last record of the response has been read. A cursor
	//! destroyed while this is false abandons the connection.
	bool complete() const {
		return complete_;
	}

private:
	friend class Session;
	RowCursor(Session &session, size_t parser_limit);

	//! Read one DIME record, unseal it, and feed the parser.
	void Pump();
	void Feed(const Bytes &plain);
	void CheckHead();

	Session &session_;
	std::unique_ptr<sealing::Unsealer> unsealer_;
	RowStreamParser parser_;

	//! The plaintext prefix, for the checks that need a document rather than a
	//! row: is this XML at all, is it a fault, what is the SessionId. Bounded,
	//! because it exists to inspect a header and not to buffer a rowset.
	std::string head_;
	static const size_t HEAD_LIMIT = 64 * 1024;
	size_t parser_limit_;

	bool head_checked_ = false;
	bool complete_ = false;
	bool drained_ = false;
};

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

	//! Execute, and stream the rows back instead of materialising them.
	//!
	//! Same read-only validation as Execute - the guard is on the statement, so
	//! it does not care how the answer is read. The returned cursor borrows this
	//! session; destroy it first.
	std::unique_ptr<RowCursor> ExecuteCursor(const std::string &statement, const std::string &catalog = std::string(),
											 size_t parser_limit = RowCursor::DEFAULT_PARSER_LIMIT);

	State state() const {
		return state_;
	}
	const NegotiatedTerms &terms() const {
		return terms_;
	}
	//! For diagnostics. Never contains a principal, realm or token.
	std::string SealDescription() const;

private:
	friend class RowCursor;
	void RequireAuthenticated() const;
	//! Send a request and leave the response unread, for a streaming caller.
	void SendRequest(const std::string &payload);
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
