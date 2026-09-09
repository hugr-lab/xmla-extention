//===----------------------------------------------------------------------===//
// The GSS-API handshake, carried inside Authenticate SOAP messages.
//
// [MS-SSAS] "Authentication and Encryption":
//   "To use an authenticated or encrypted connection using TCP, both the client
//    and server MUST use GSS-API [RFC4178]. ... The client sends its security
//    token using the Authenticate request and the server responds with its
//    security token in the AuthenticateResponse message. This exchange ...
//    continues back and forth until GSS-API reports completion or error."
//
// ONE loop serves Kerberos and NTLM: the specification's exchange is
// mechanism-agnostic, and so is this (FR-013).
//
// Nothing in this file may log a token. A SPNEGO token carries the principal,
// the realm and the target service (constitution I).
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/gss_context.hpp"

#include <functional>
#include <string>

namespace xmla {
namespace auth {

//! A handshake needing more rounds than this is a loop, not progress.
static const int MAX_ROUNDS = 10;

//! Performs one round trip: send a base64 token, return the response document.
using SendAuthenticate = std::function<std::string(const std::string &)>;

//! Pull the server's base64 token out of an AuthenticateResponse.
std::string ExtractToken(const std::string &response_xml);

//! Run the token exchange to completion.
//!
//! Driven by the security layer reporting completion, exactly as the spec
//! describes, rather than by counting messages.
void Handshake(GssContext &context, const SendAuthenticate &send, int max_rounds = MAX_ROUNDS);

std::string Base64Encode(const Bytes &in);
//! Returns false on invalid input rather than throwing: the caller turns that
//! into a protocol error with its own context.
bool Base64Decode(const std::string &in, Bytes &out);

}  // namespace auth
}  // namespace xmla
