#include "xmla_storage.hpp"

#include "catalog/xmla_catalog.hpp"
#include "catalog/xmla_transaction.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

namespace {

unique_ptr<Catalog> XmlaAttach(optional_ptr<StorageExtensionInfo>, ClientContext &context, AttachedDatabase &db,
							   const string &, AttachInfo &info, AttachOptions &options) {
	// The path is the connection string: ATTACH 'host=… port=…' AS aw (TYPE xmla)
	auto params = XmlaConnectionParams::FromString(info.path);

	// ATTACH options are accepted as an alternative to the connection string,
	// which is what a user reaching for `(TYPE xmla, SECRET my_secret)` expects.
	for (auto &option : options.options) {
		const auto key = StringUtil::Lower(option.first);
		if (key == "secret") {
			params.secret_name = option.second.ToString();
		} else if (key == "catalog") {
			params.catalog = option.second.ToString();
		} else if (key == "type" || key == "read_only") {
			continue;  // handled by DuckDB
		} else {
			throw BinderException("xmla: unknown ATTACH option '%s'. Known: secret, catalog", key);
		}
	}

	// READ_ONLY is not merely permitted, it is the only mode.
	//
	// An earlier version set `options.access_mode = READ_ONLY` here and was dead
	// code twice over. AttachedDatabase's constructor reads access_mode and sets
	// `type` BEFORE it calls this function (attached_database.cpp:166-170), so
	// the mutation came too late to be seen; and the default is
	// AccessMode::AUTOMATIC, not READ_WRITE, so on a plain `ATTACH ... (TYPE
	// xmla)` the branch was never entered at all. The attachment was
	// READ_WRITE_DATABASE and duckdb_databases().readonly reported false.
	//
	// SetReadOnlyDatabase() sets `type` directly and works from here, so
	// DuckDB's own guard applies as well as the catalog's refusals.
	db.SetReadOnlyDatabase();

	// An EXPLICIT request to attach read-write is refused rather than quietly
	// downgraded: the caller asked for something this extension cannot provide,
	// and saying so is more useful than appearing to comply. AUTOMATIC — the
	// default, meaning "unspecified" — is not a request and is left alone.
	if (options.access_mode == AccessMode::READ_WRITE) {
		throw BinderException(
			"xmla: an Analysis Services attachment is read-only; "
			"remove READ_ONLY false from the ATTACH options");
	}

	// Resolve at ATTACH so a missing port or an absent secret is reported HERE
	// rather than on the first query. Resolve reads the secret before applying
	// defaults, which is the whole reason it is one call: doing it in two steps
	// let the default mechanism beat a secret carrying mechanism='ntlm', and
	// every connection then attempted Kerberos.
	//
	// The password is discarded: ATTACH opens no connection, and the catalog
	// re-resolves when it needs one.
	params.ResolveAndDiscardPassword(context);

	// NOTE: no connection is made here. ATTACH deliberately does not contact the
	// instance: schemas load on first use, so attaching an unreachable instance
	// succeeds and the first query reports the failure. That is the opposite of
	// the neighbouring mssql extension's eager validation, and the reason is the
	// fixture: an instance that is powered off between sessions would make every
	// ATTACH in a script fail, when the script may not touch that catalog at all.
	return make_uniq<XmlaCatalog>(db, std::move(params));
}

unique_ptr<TransactionManager> XmlaCreateTransactionManager(optional_ptr<StorageExtensionInfo>, AttachedDatabase &db,
															Catalog &) {
	return make_uniq<XmlaTransactionManager>(db);
}

}  // namespace

void RegisterXmlaStorage(ExtensionLoader &loader) {
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = XmlaAttach;
	storage->create_transaction_manager = XmlaCreateTransactionManager;
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	StorageExtension::Register(config, "xmla", std::move(storage));
}

}  // namespace duckdb
