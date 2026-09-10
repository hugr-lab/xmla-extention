#include "catalog/xmla_catalog.hpp"

#include "catalog/xmla_schema_entry.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "duckdb/storage/database_size.hpp"
#include "xmla/errors.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

namespace {

[[noreturn]] void Refuse(const char *what) {
	throw NotImplementedException(
		"xmla: %s is not supported. This extension is READ-ONLY: it "
		"contains no path that creates, alters, refreshes or deletes a "
		"server-side object. Grant the connecting account read-only "
		"permissions on the server as well; that is the only control "
		"that cannot be reasoned around.",
		what);
}

//! DBSCHEMA_CATALOGS.TYPE, as observed on a live SQL Server 2022 pair: the
//! tabular instance reports "3" and the multidimensional one "0".
//!
//! COMPATIBILITY_LEVEL does NOT distinguish them — multidimensional databases
//! use 1050/1100/1103, so any MD database created on SQL Server 2012 or later
//! reports 1100+ and a ">= 1100 means tabular" rule labels it tabular. That is
//! the confident-and-wrong answer this avoids.
//!
//! Two samples, so anything else is treated as NOT tabular: the consequence of
//! guessing wrong in that direction is a clear "rows cannot be read as a table"
//! message, while guessing tabular wrongly produces a DAX error from the server.
bool LooksTabular(const xmla::Rowset &catalogs, const std::string &name) {
	for (size_t i = 0; i < catalogs.size(); i++) {
		const auto row = catalogs.Row(i);
		const std::string *catalog_name = row.Find("CATALOG_NAME");
		if (!catalog_name || *catalog_name != name) {
			continue;
		}
		const std::string *type = row.Find("TYPE");
		return type && *type == "3";
	}
	return false;
}

}  // namespace

XmlaCatalog::XmlaCatalog(AttachedDatabase &db, XmlaConnectionParams params) : Catalog(db), params_(std::move(params)) {}

XmlaCatalog::~XmlaCatalog() noexcept = default;

void XmlaCatalog::Initialize(bool) {
	// Nothing at ATTACH. Schemas load on first use so attaching does not pay for
	// metadata a session may never ask for — and, more importantly, so ATTACH
	// does not fail because one model out of several is unreadable.
}

string XmlaCatalog::GetCatalogType() {
	return "xmla";
}

void XmlaCatalog::LoadSchemas(ClientContext &context) {
	std::lock_guard<std::mutex> guard(load_lock_);
	if (loaded_) {
		return;
	}

	xmla::Rowset catalogs;
	try {
		auto session = OpenSession(context, params_);
		catalogs = session->Discover("DBSCHEMA_CATALOGS");
		session->Close();
	} catch (const xmla::XmlaError &error) {
		RethrowXmlaError(error);
	}

	for (size_t i = 0; i < catalogs.size(); i++) {
		const std::string *found = catalogs.Row(i).Find("CATALOG_NAME");
		if (!found || found->empty()) {
			continue;
		}
		const std::string &model = *found;
		// If ATTACH named a catalog, present only that one: an instance can hold
		// several models and a session usually wants one.
		if (!params_.catalog.empty() && !StringUtil::CIEquals(params_.catalog, model)) {
			continue;
		}
		CreateSchemaInfo info;
		// CreateSchemaInfo encodes its path as [catalog, parents..., new_schema,
		// <empty name>], so the schema's own name goes in the SCHEMA slot and the
		// trailing name stays empty. Setting info.name instead leaves
		// SchemaName() empty and every lookup misses.
		info.SetSchema(Identifier(model));
		schemas_[model] = make_uniq<XmlaSchemaEntry>(*this, info, params_, LooksTabular(catalogs, model));
	}

	if (!params_.catalog.empty() && schemas_.empty()) {
		// Naming a catalog that is not there is a mistake worth reporting, not an
		// empty catalog to puzzle over. An empty list WITHOUT a named catalog is
		// a meaningful answer — "none visible to this account" — and is left
		// alone.
		throw IOException("xmla: no catalog named '%s' is visible to this account", params_.catalog);
	}
	loaded_ = true;
}

optional_ptr<CatalogEntry> XmlaCatalog::CreateSchema(CatalogTransaction, CreateSchemaInfo &) {
	Refuse("CREATE SCHEMA");
}

void XmlaCatalog::DropSchema(ClientContext &, DropInfo &) {
	Refuse("DROP SCHEMA");
}

void XmlaCatalog::ScanSchemas(ClientContext &context, std::function<void(SchemaCatalogEntry &)> callback) {
	LoadSchemas(context);

	// Snapshot under the lock, then RELEASE it before calling back.
	//
	// The callback for SHOW ALL TABLES goes on to XmlaSchemaEntry::LoadTables,
	// which opens a session and issues two DISCOVER round trips — so holding
	// this catalog-wide mutex across it serialised unrelated concurrent queries
	// on the same attachment for the duration of every model's metadata fetch.
	// Worse, load_lock_ is a plain std::mutex, so any callback path that
	// re-entered LookupSchema or ScanSchemas would be undefined behaviour rather
	// than a recursive acquire. The entries outlive the lock: they are owned by
	// schemas_ and never erased.
	vector<reference<SchemaCatalogEntry>> snapshot;
	{
		std::lock_guard<std::mutex> guard(load_lock_);
		for (auto &entry : schemas_) {
			snapshot.push_back(entry.second->Cast<SchemaCatalogEntry>());
		}
	}
	for (auto &schema : snapshot) {
		callback(schema.get());
	}
}

optional_ptr<SchemaCatalogEntry> XmlaCatalog::LookupSchema(CatalogTransaction transaction,
														   const EntryLookupInfo &lookup_info,
														   OnEntryNotFound if_not_found) {
	const auto &schema_name = lookup_info.GetEntryName();
	if (!transaction.HasContext()) {
		if (if_not_found == OnEntryNotFound::RETURN_NULL) {
			return nullptr;
		}
		throw IOException("xmla: schema lookup needs a client context");
	}
	LoadSchemas(transaction.GetContext());

	std::lock_guard<std::mutex> guard(load_lock_);
	// DEFAULT_SCHEMA resolves to the only model when there is exactly one, so
	// `SELECT * FROM aw.SomeTable` works without naming the model. With several,
	// it does not guess.
	if (schema_name.empty() || schema_name == DEFAULT_SCHEMA) {
		if (schemas_.size() == 1) {
			return schemas_.begin()->second->Cast<SchemaCatalogEntry>();
		}
	}
	const auto found = schemas_.find(schema_name);
	if (found != schemas_.end()) {
		return found->second->Cast<SchemaCatalogEntry>();
	}
	if (if_not_found == OnEntryNotFound::RETURN_NULL) {
		return nullptr;
	}
	throw CatalogException("xmla: no catalog named '%s' is visible to this account", schema_name);
}

DatabaseSize XmlaCatalog::GetDatabaseSize(ClientContext &) {
	// Unknown rather than zero. Zero reads as "empty", which is a different and
	// wrong claim.
	DatabaseSize size;
	return size;
}

bool XmlaCatalog::InMemory() {
	return false;
}

string XmlaCatalog::GetDBPath() {
	// NOT the host. This string surfaces in duckdb_databases() and in error
	// messages, and constitution I forbids a hostname reaching either.
	return "xmla";
}

PhysicalOperator &XmlaCatalog::PlanInsert(ClientContext &, PhysicalPlanGenerator &, LogicalInsert &,
										  optional_ptr<PhysicalOperator>) {
	Refuse("INSERT");
}

PhysicalOperator &XmlaCatalog::PlanCreateTableAs(ClientContext &, PhysicalPlanGenerator &, LogicalCreateTable &,
												 PhysicalOperator &) {
	Refuse("CREATE TABLE AS SELECT");
}

PhysicalOperator &XmlaCatalog::PlanDelete(ClientContext &, PhysicalPlanGenerator &, LogicalDelete &,
										  PhysicalOperator &) {
	Refuse("DELETE");
}

PhysicalOperator &XmlaCatalog::PlanUpdate(ClientContext &, PhysicalPlanGenerator &, LogicalUpdate &,
										  PhysicalOperator &) {
	Refuse("UPDATE");
}

unique_ptr<LogicalOperator> XmlaCatalog::BindCreateIndex(Binder &, CreateStatement &, TableCatalogEntry &,
														 unique_ptr<LogicalOperator>) {
	Refuse("CREATE INDEX");
}

}  // namespace duckdb
