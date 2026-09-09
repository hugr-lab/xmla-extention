//===----------------------------------------------------------------------===//
// SOAP envelopes for the three operations [MS-SSAS] defines.
//
// Authenticate, Discover and Execute - the same three the HTTP binding uses,
// which is why the envelopes and all response parsing are shared between
// bindings and only the framing below them differs.
//
// READ-ONLY BY CONSTRUCTION (constitution II): there is no builder here for
// Create, Alter, Delete or Refresh, and no parameter through which a statement
// could become one. The capability is ABSENT, not gated.
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

//! Run a read-only analytic statement. There is no mutating builder anywhere in
//! this file, so no argument here can reach one.
std::string Execute(const std::string &statement, const std::string &catalog, const std::string &session_id);

//! Escape text for an XML text node or attribute value.
std::string XmlEscape(const std::string &in);

}  // namespace envelopes
}  // namespace xmla
