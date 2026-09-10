//===----------------------------------------------------------------------===//
// Turning a DuckDB-facing connection description into an xmla::Session.
//
// This is above the protocol layer and may include DuckDB headers; nothing
// under src/xmla/ may, and scripts/ci/check_layering.sh enforces that.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "xmla/client.hpp"
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

	//! Fill anything still unset from a DuckDB secret. Returns the password,
	//! which the caller passes directly to the session and does not retain.
	std::string ApplySecret(ClientContext &context);

	//! Apply defaults for anything neither the connection string nor the secret
	//! set. Called after ApplySecret, which is the whole point.
	void ApplyDefaults();

	void Validate() const;

	xmla::ConnectionTarget Target() const;
	xmla::Credential Credential() const;
};

//! Open an authenticated session. The password is read here and dropped here.
std::unique_ptr<xmla::Session> OpenSession(ClientContext &context, XmlaConnectionParams params);

}  // namespace duckdb
