#include "xmla_connection.hpp"

#include "duckdb/main/secret/secret_manager.hpp"
#include "xmla/connection_string.hpp"
#include "xmla/errors.hpp"

#include <algorithm>
#include <cstdlib>

namespace duckdb {

namespace {

std::string LowerAscii(const std::string &in) {
	std::string out = in;
	std::transform(out.begin(), out.end(), out.begin(),
				   [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; });
	return out;
}

//! strtoul, not atoi: atoi truncates silently, so `port=65538` would become
//! port 2 — reintroducing the guess-and-hang this option set exists to avoid.
uint16_t ParsePort(const std::string &value) {
	char *end = nullptr;
	const unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
	if (value.empty() || (end && *end != '\0') || parsed < 1 || parsed > 65535) {
		throw BinderException("xmla: port must be a number in 1..65535");
	}
	return static_cast<uint16_t>(parsed);
}

double ParseTimeout(const std::string &value) {
	char *end = nullptr;
	const double parsed = std::strtod(value.c_str(), &end);
	if (value.empty() || (end && *end != '\0') || !(parsed > 0)) {
		throw BinderException("xmla: timeout must be a positive number of seconds");
	}
	return parsed;
}

}  // namespace

XmlaConnectionParams XmlaConnectionParams::FromString(const std::string &connection) {
	XmlaConnectionParams params;

	// Tokenising lives in the protocol layer (xmla::ParseConnectionString) so the
	// hermetic suite can test it. It shipped once with a bug those tests catch
	// immediately: it split only on ';' while the documented form is
	// space-separated, so `host=x port=2383` parsed as one pair and the port
	// silently stayed 0 — surfacing as "port is required" against a string that
	// plainly contains one.
	std::map<std::string, std::string> options;
	try {
		options = xmla::ParseConnectionString(connection);
	} catch (const xmla::XmlaError &error) {
		throw BinderException("xmla: %s", error.what());
	}

	for (const auto &option : options) {
		const std::string &key = option.first;
		const std::string &value = option.second;
		if (key == "host") {
			params.host = value;
		} else if (key == "port") {
			params.port = ParsePort(value);
		} else if (key == "mechanism") {
			params.mechanism = LowerAscii(value);
		} else if (key == "user") {
			params.user = value;
		} else if (key == "catalog") {
			params.catalog = value;
		} else if (key == "spn") {
			params.spn = value;
		} else if (key == "instance") {
			params.instance = value;
		} else if (key == "use_port") {
			params.use_port = (LowerAscii(value) == "true" || value == "1");
		} else if (key == "timeout") {
			params.timeout_seconds = ParseTimeout(value);
		} else if (key == "secret") {
			params.secret_name = value;
		} else if (key == "password") {
			// Refused, not accepted-and-hidden. A password in a connection string
			// reaches the query log, the plan, and every error that echoes the
			// statement. Secrets exist for this.
			throw BinderException(
				"xmla: a password may not be given in the connection string; "
				"use CREATE SECRET (TYPE xmla, ...) and pass secret=<name>");
		} else {
			// An unknown key is an ERROR. Ignoring one means a typo'd
			// `mechansim=ntlm` silently authenticates with the default mechanism
			// instead — the caller asked for something and got something else.
			throw BinderException(
				"xmla: unknown connection option '%s'. Known: host, port, "
				"mechanism, user, catalog, spn, instance, use_port, timeout, secret",
				key);
		}
	}
	return params;
}

std::string XmlaConnectionParams::ApplySecret(ClientContext &context) {
	if (secret_name.empty()) {
		return std::string();
	}
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto entry = manager.GetSecretByName(transaction, secret_name);
	if (!entry) {
		throw BinderException(
			"xmla: secret '%s' not found. Create it with: CREATE SECRET %s "
			"(TYPE xmla, MECHANISM 'ntlm', USER '...', PASSWORD '...')",
			secret_name, secret_name);
	}
	const auto &secret = dynamic_cast<const KeyValueSecret &>(*entry->secret);

	auto take = [&](const char *key, std::string &target) {
		if (!target.empty()) {
			return;	 // the connection string wins; it is more specific
		}
		const Value value = secret.TryGetValue(key);
		if (!value.IsNull()) {
			target = value.ToString();
		}
	};
	take("user", user);
	take("mechanism", mechanism);
	take("host", host);
	take("spn", spn);

	if (port == 0) {
		const Value port_value = secret.TryGetValue("port");
		if (!port_value.IsNull()) {
			port = static_cast<uint16_t>(port_value.GetValue<int64_t>());
		}
	}

	// Read and returned, never stored on this struct.
	const Value password_value = secret.TryGetValue("password");
	if (!password_value.IsNull()) {
		return password_value.ToString();
	}
	return std::string();
}

void XmlaConnectionParams::ApplyDefaults() {
	if (mechanism.empty()) {
		// Kerberos is the default because it is what a domain deployment uses.
		// It is applied HERE, after the secret has had its say — applying it at
		// construction made the default beat a secret's mechanism='ntlm', and
		// every connection then attempted Kerberos regardless.
		mechanism = "kerberos";
	}
}

void XmlaConnectionParams::Validate() const {
	if (host.empty()) {
		throw BinderException("xmla: host is required");
	}
	if (port == 0) {
		// No default, deliberately: a default would invite guessing between a
		// default instance's well-known port and a named instance's pinned one,
		// and guessing wrong presents as a hang. There is also no
		// named-instance redirector to ask (research D9).
		throw BinderException(
			"xmla: port is required and must be pinned. There is no default and "
			"no named-instance redirector; pin it in msmdsrv.ini");
	}
	if (timeout_seconds <= 0) {
		throw BinderException("xmla: timeout must be positive; unbounded waits are not offered");
	}
}

xmla::ConnectionTarget XmlaConnectionParams::Target() const {
	xmla::ConnectionTarget target;
	target.host = host;
	target.port = port;
	target.timeout_seconds = timeout_seconds;
	return target;
}

xmla::Credential XmlaConnectionParams::Credential() const {
	xmla::Credential credential;
	credential.mechanism = mechanism;
	credential.principal = user;
	credential.spn_override = spn;
	credential.instance = instance;
	credential.use_port = use_port;
	return credential;
}

std::string XmlaConnectionParams::Resolve(ClientContext &context) {
	// Order matters and is enforced here rather than trusted to callers.
	const std::string password = ApplySecret(context);
	ApplyDefaults();
	Validate();
	return password;
}

std::unique_ptr<xmla::Session> OpenSession(ClientContext &context, XmlaConnectionParams params) {
	// The password lives for the duration of this function and no longer. It is
	// handed to GssContext::Create, which passes it to the security layer without
	// retaining it, and is never placed on the Session.
	const std::string password = params.Resolve(context);
	if (getenv("XMLA_DEBUG")) {
		// SHAPES ONLY, never values (constitution I). This exists because the
		// bug it found was invisible any other way: "the connection string wins
		// over the secret" was implemented as "non-empty wins", so mechanism's
		// non-empty DEFAULT beat a secret's mechanism='ntlm' and every
		// connection silently attempted Kerberos.
		fprintf(stderr, "[xmla] mechanism=%s principal_set=%d password_len=%zu port=%u\n", params.mechanism.c_str(),
				params.user.empty() ? 0 : 1, password.size(), static_cast<unsigned>(params.port));
	}

	auto session = make_uniq<xmla::Session>(params.Target(), params.Credential());
	auto gss = xmla::GssContext::Create(params.Credential(), params.host, params.port, password);
	session->Open(nullptr, std::move(gss));
	return session;
}

}  // namespace duckdb
