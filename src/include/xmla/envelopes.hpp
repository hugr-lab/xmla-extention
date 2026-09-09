//===----------------------------------------------------------------------===//
// SOAP envelopes for the three operations [MS-SSAS] defines.
//
// Authenticate, Discover and Execute - the same three the HTTP binding uses,
// which is why the envelopes and all response parsing are shared between
// bindings and only the framing below them differs.
//
// Read-only. The guarantee is NOT uniform across the three, and saying so
// precisely matters more than saying it strongly:
//
//   Discover      read-only BY CONSTRUCTION. There is no builder here for
//                 Create, Alter, Delete or Refresh, so no argument can reach
//                 one. The capability is absent, not gated.
//
//   Execute       read-only BY VALIDATION, because <Statement> is the entry
//                 point to the WHOLE command surface, not just to queries. MDX
//                 writeback (UPDATE CUBE), DMX (INSERT INTO, DELETE FROM, DROP
//                 MINING MODEL) and CALL <stored procedure> all travel through
//                 exactly this element. Absence of a Create/Alter builder
//                 removes one route to mutation and not the others, so the
//                 statement itself is checked against an allowlist of leading
//                 keywords.
//
// An earlier version of this comment claimed construction for both. It was
// wrong, and the test that "proved" it only asserted the emitted string lacked
// the literals <Create/<Alter/<Delete/<Refresh -- which no MDX or DMX mutation
// contains, so it could not have failed.
//===----------------------------------------------------------------------===//
#pragma once

#include <map>
#include <string>

namespace xmla {
namespace envelopes {

extern const char *const SOAP_NS;
extern const char *const XMLA_NS;
//! Authenticate lives in a DIFFERENT namespace from Discover/Execute. Confirmed
//! against the worked example in [MS-SSAS] "Authentication", and confirmed the
//! hard way by a live server: sending Authenticate under the XMLA namespace is
//! rejected with "The Authenticate element ... cannot appear under
//! Envelope/Body".
extern const char *const EXT_NS;

using Restrictions = std::map<std::string, std::string>;

//! Carry one GSS-API security token to the server.
std::string Authenticate(const std::string &token_b64);

//! BeginSession on the first request, Session with the id on every later one.
//! [MS-SSAS] "Initialization for Non-HTTP Transport": the server returns a
//! SessionId that every later request MUST carry.
std::string SessionHeader(const std::string &session_id);

std::string Discover(const std::string &request_type, const Restrictions &restrictions, const std::string &catalog,
					 const std::string &session_id);

//! Run a read-only analytic statement.
//!
//! Throws ProtocolError if the statement is not a query. See RejectIfMutating.
std::string Execute(const std::string &statement, const std::string &catalog, const std::string &session_id);

//! Refuse anything whose first significant keyword is not a query keyword.
//!
//! An ALLOWLIST, not a denylist: the set of ways to mutate an Analysis Services
//! database through <Statement> is open-ended (MDX writeback, DMX, stored
//! procedure CALL, and whatever a future server adds), while the set of ways to
//! ask a question is small and stable. A denylist would have to be complete to
//! be worth anything; this only has to be right about SELECT, EVALUATE, WITH,
//! DEFINE and VAR.
//!
//! This is a GUARD, not a proof. It is deliberately conservative and it is not
//! a substitute for granting the connecting account read-only permissions on
//! the server, which is the only control that cannot be reasoned around.
void RejectIfMutating(const std::string &statement);

//! Escape text for an XML text node or attribute value.
std::string XmlEscape(const std::string &in);

}  // namespace envelopes
}  // namespace xmla
