#include "xmla_secret.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

namespace {

//! The fields a secret may carry. `password` is here; everything else is also
//! accepted in a connection string, where the connection string wins because it
//! is the more specific of the two.
void RedactPasswordField(KeyValueSecret &secret) {
	// DuckDB redacts named keys when a secret is displayed. Without this,
	// `SELECT * FROM duckdb_secrets()` prints the password in clear.
	secret.redact_keys.insert(Identifier("password"));
}

unique_ptr<BaseSecret> CreateXmlaSecret(ClientContext &, CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		// Analysis Services is reached by host and port rather than by a path
		// prefix, so there is no meaningful path scope. An empty prefix makes the
		// secret apply wherever it is named explicitly.
		scope.push_back("");
	}
	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	for (const auto &named : input.options) {
		// CreateSecretInput::options is keyed on a plain string, unlike a table
		// function's named parameters, which are Identifiers.
		const auto key = StringUtil::Lower(named.first);
		if (key == "host" || key == "port" || key == "mechanism" || key == "user" || key == "password" ||
			key == "spn") {
			secret->secret_map[Identifier(key)] = named.second;
			continue;
		}
		// A BACKSTOP, not the main check. DuckDB validates against the declared
		// named_parameters before this runs, so a misspelled `passwrd` is
		// rejected there with "Unknown parameter". This catches the state a
		// future edit could create: a field declared in named_parameters and not
		// handled here, which would otherwise be accepted and silently dropped.
		throw InvalidInputException(
			"xmla secret: unknown field '%s'. Known: host, port, "
			"mechanism, user, password, spn",
			key);
	}

	RedactPasswordField(*secret);
	return secret;
}

}  // namespace

void RegisterXmlaSecretType(ExtensionLoader &loader) {
	SecretType type;
	type.name = "xmla";
	type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	type.default_provider = "config";
	loader.RegisterSecretType(type);

	CreateSecretFunction function = {"xmla", "config", CreateXmlaSecret};
	function.named_parameters["host"] = LogicalType::VARCHAR;
	function.named_parameters["port"] = LogicalType::INTEGER;
	function.named_parameters["mechanism"] = LogicalType::VARCHAR;
	function.named_parameters["user"] = LogicalType::VARCHAR;
	function.named_parameters["password"] = LogicalType::VARCHAR;
	function.named_parameters["spn"] = LogicalType::VARCHAR;
	loader.RegisterFunction(function);
}

}  // namespace duckdb
