//===----------------------------------------------------------------------===//
// The GSS-API security context, and the two seal providers built over it.
//
// Nothing in this file may log a token, at any level, in any form - not
// truncated, not hashed, not base64. A GSS/SPNEGO token carries the principal,
// the realm, the target service and often the machine name (constitution I).
// GSS status messages are equally unsafe: gss_display_status routinely names
// the principal and realm, so they are NOT propagated into error text.
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/seal_provider.hpp"

#include <memory>
#include <string>

namespace xmla {

//! What the security layer authenticates with.
//!
//! Deliberately has NO password field. Where NTLM needs one on a standalone
//! server it is passed to GssContext::Create directly and never retained, so no
//! formatting or logging of a Credential can leak it (FR-014).
struct Credential {
	std::string mechanism = "kerberos";	 //!< kerberos | negotiate | ntlm
	std::string principal;				 //!< empty means the ambient identity
	std::string service = "MSOLAPSvc.3";
	std::string instance;	   //!< a named instance, if the SPN is registered that way
	bool use_port = false;	   //!< ask for MSOLAPSvc.3/host:port, as ADOMD does on SSPI
	std::string spn_override;  //!< full override, service class included

	//! The SPN to request. NTLM ignores it; Kerberos does not.
	//!
	//! The default is the PORTLESS form, and that is a deliberate departure from
	//! the reference client. ADOMD's CalculateNTAuthenticationSPN calls DsMakeSpn
	//! *with* the port, producing MSOLAPSvc.3/<host>:<port> - but that justifies
	//! the string only on SSPI, where the SPN is used as written. On GSSAPI the
	//! host half goes through krb5 canonicalization and realm determination, so
	//! `host:2383` leaves a trailing component no [domain_realm] mapping can
	//! resolve, and would request a ticket in the wrong realm on exactly the
	//! platform this extension exists for. See research D8; neither form has been
	//! tested against a live Kerberos-speaking instance.
	std::string Target(const std::string &host, uint16_t port) const;
};

class GssContext {
public:
	virtual ~GssContext() = default;

	//! Establish or advance the context. Returns the token to send, or empty when
	//! there is nothing more to send. `IsComplete()` reports completion.
	virtual Bytes Step(const Bytes &in_token) = 0;
	virtual bool IsComplete() const = 0;

	//! Build a seal provider for the established context, choosing the
	//! implementation by capability probe rather than by mechanism name.
	virtual std::unique_ptr<SealProvider> MakeSealProvider() = 0;

	//! Create a real GSS context. `password` is for the standalone (non-domain)
	//! case, where NTLM has no ambient identity to draw on; it goes straight to
	//! the security layer and is never stored.
	static std::unique_ptr<GssContext> Create(const Credential &credential, const std::string &host, uint16_t port,
											  const std::string &password);
};

}  // namespace xmla
