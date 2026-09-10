//===----------------------------------------------------------------------===//
// Turning a DuckDB-facing connection description into an xmla::Session.
//
// This is above the protocol layer and may include DuckDB headers; nothing
// under src/xmla/ may, and scripts/ci/check_layering.sh enforces that.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "xmla/client.hpp"
#include "xmla/errors.hpp"
#include "xmla/gss_context.hpp"

#include <memory>
#include <string>

namespace duckdb {

//! Everything needed to open a session, gathered from a connection string, a
//! secret, or both.
//!
//! The password is NOT a member. It is fetched from the secret at the moment a
//! session is opened and handed straight to the security layer, so it is never
//! stored on anything a caller holds, printed, or serialised into a plan.
struct XmlaConnectionParams {
	std::string host;
	uint16_t port = 0;
	//! EMPTY until resolved, not "kerberos".
	//!
	//! "The connection string wins over the secret" was implemented as
	//! "non-empty wins" — which silently made the DEFAULT win too, so a secret
	//! carrying mechanism='ntlm' was ignored and every connection attempted
	//! Kerberos. A default has to be applied AFTER the secret, not before.
	std::string mechanism;
	std::string user;
	std::string catalog;
	std::string spn;
	std::string instance;
	bool use_port = false;
	double timeout_seconds = xmla::DEFAULT_TIMEOUT_SECONDS;
	//! Name of a DuckDB secret to draw the credential from, if any.
	std::string secret_name;

	//! Parse `host=... port=... mechanism=...`.
	//!
	//! Keys are case-insensitive; unknown keys are an ERROR rather than being
	//! ignored, because a silently dropped `mechanism=ntlm` authenticates with
	//! something the caller did not ask for.
	static XmlaConnectionParams FromString(const std::string &connection);

	//! Resolve the secret, apply defaults, and validate — IN THAT ORDER.
	//!
	//! One entry point, because the order is not incidental and getting it wrong
	//! is silent. It has now been got wrong twice, in two places: applying
	//! defaults before the secret makes the DEFAULT beat the secret, so a secret
	//! carrying mechanism='ntlm' was ignored and every connection attempted
	//! Kerberos. Splitting the steps into public methods invited exactly that,
	//! so they are private now and this is the only way in.
	//!
	//! Returns the password, which the caller hands straight to the security
	//! layer and does not retain. Calling this twice is fine and cheap.
	std::string Resolve(ClientContext &context);

	//! Resolve without keeping the password — for ATTACH, which validates the
	//! parameters but opens no connection.
	void ResolveAndDiscardPassword(ClientContext &context) {
		(void)Resolve(context);
	}

	xmla::ConnectionTarget Target() const;
	xmla::Credential Credential() const;

private:
	std::string ApplySecret(ClientContext &context);
	void ApplyDefaults();
	void Validate() const;
};

//! Open an authenticated session. The password is read here and dropped here.
std::unique_ptr<xmla::Session> OpenSession(ClientContext &context, XmlaConnectionParams params);

//! Translate a protocol-layer failure into the DuckDB exception that matches it.
//!
//! The protocol layer's categories exist so an operator can act without parsing
//! message text, and throwing IOException for all of them threw that away: a
//! wrong password, a refused permission and an unreachable host all arrived as
//! "IO Error". DuckDB surfaces the exception type in `error_type`, so the
//! mapping is visible to a caller and not only to a human reading the message.
[[noreturn]] void RethrowXmlaError(const xmla::XmlaError &error);

}  // namespace duckdb
