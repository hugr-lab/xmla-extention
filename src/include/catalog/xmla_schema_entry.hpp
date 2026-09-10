//===----------------------------------------------------------------------===//
// One SSAS catalog (model/database) as a DuckDB schema.
//
// Read-only by construction: every Create* and Alter override refuses. This is
// T-037, and it is written out rather than inherited because a base class that
// quietly accepted a CREATE would make the extension's central guarantee depend
// on DuckDB's defaults.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "xmla_connection.hpp"

#include <map>
#include <mutex>

namespace duckdb {

class XmlaSchemaEntry : public SchemaCatalogEntry {
public:
	XmlaSchemaEntry(Catalog &catalog, CreateSchemaInfo &info, XmlaConnectionParams params, bool tabular);

	optional_ptr<CatalogEntry> CreateTable(CatalogTransaction transaction, BoundCreateTableInfo &info) override;
	optional_ptr<CatalogEntry> CreateFunction(CatalogTransaction transaction, CreateFunctionInfo &info) override;
	optional_ptr<CatalogEntry> CreateIndex(CatalogTransaction transaction, CreateIndexInfo &info,
										   TableCatalogEntry &table) override;
	optional_ptr<CatalogEntry> CreateView(CatalogTransaction transaction, CreateViewInfo &info) override;
	optional_ptr<CatalogEntry> CreateSequence(CatalogTransaction transaction, CreateSequenceInfo &info) override;
	optional_ptr<CatalogEntry> CreateTableFunction(CatalogTransaction transaction,
												   CreateTableFunctionInfo &info) override;
	optional_ptr<CatalogEntry> CreateCopyFunction(CatalogTransaction transaction,
												  CreateCopyFunctionInfo &info) override;
	optional_ptr<CatalogEntry> CreatePragmaFunction(CatalogTransaction transaction,
													CreatePragmaFunctionInfo &info) override;
	optional_ptr<CatalogEntry> CreateCollation(CatalogTransaction transaction, CreateCollationInfo &info) override;
	optional_ptr<CatalogEntry> CreateType(CatalogTransaction transaction, CreateTypeInfo &info) override;
	void Alter(CatalogTransaction transaction, AlterInfo &info) override;
	void DropEntry(ClientContext &context, DropInfo &info) override;

	void Scan(ClientContext &context, CatalogType type, const std::function<void(CatalogEntry &)> &callback) override;
	void Scan(CatalogType type, const std::function<void(CatalogEntry &)> &callback) override;
	optional_ptr<CatalogEntry> LookupEntry(CatalogTransaction transaction, const EntryLookupInfo &lookup_info) override;

private:
	//! Fetch DBSCHEMA_TABLES and DBSCHEMA_COLUMNS for this model, once.
	//!
	//! LAZY, and per schema. Fetching every model's tables at ATTACH would make
	//! attaching an instance with several models pay for all of them, and a
	//! session that only ever queries one would pay for the rest.
	void LoadTables(ClientContext &context);

	XmlaConnectionParams params_;
	bool tabular_;
	std::mutex load_lock_;
	bool loaded_ = false;
	//! Keyed on the table name, case-insensitively, as SQL expects.
	case_insensitive_map_t<unique_ptr<CatalogEntry>> tables_;
};

}  // namespace duckdb
