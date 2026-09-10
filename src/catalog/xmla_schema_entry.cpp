#include "catalog/xmla_schema_entry.hpp"

#include "catalog/xmla_table_entry.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "xmla/errors.hpp"

namespace duckdb {

namespace {

//! One message, one reason, everywhere.
//!
//! T-037. Every mutating override lands here rather than each inventing its own
//! wording, so the guarantee reads the same however a caller reaches it.
[[noreturn]] void Refuse(const char *what) {
	throw NotImplementedException(
		"xmla: %s is not supported. This extension is READ-ONLY: it "
		"contains no path that creates, alters, refreshes or deletes a "
		"server-side object. Grant the connecting account read-only "
		"permissions on the server as well; that is the only control "
		"that cannot be reasoned around.",
		what);
}

}  // namespace

XmlaSchemaEntry::XmlaSchemaEntry(Catalog &catalog, CreateSchemaInfo &info, XmlaConnectionParams params, bool tabular)
	: SchemaCatalogEntry(catalog, info), params_(std::move(params)), tabular_(tabular) {}

optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateTable(CatalogTransaction, BoundCreateTableInfo &) {
	Refuse("CREATE TABLE");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateFunction(CatalogTransaction, CreateFunctionInfo &) {
	Refuse("CREATE FUNCTION");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateIndex(CatalogTransaction, CreateIndexInfo &, TableCatalogEntry &) {
	Refuse("CREATE INDEX");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateView(CatalogTransaction, CreateViewInfo &) {
	Refuse("CREATE VIEW");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateSequence(CatalogTransaction, CreateSequenceInfo &) {
	Refuse("CREATE SEQUENCE");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateTableFunction(CatalogTransaction, CreateTableFunctionInfo &) {
	Refuse("CREATE MACRO");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateCopyFunction(CatalogTransaction, CreateCopyFunctionInfo &) {
	Refuse("CREATE COPY FUNCTION");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreatePragmaFunction(CatalogTransaction, CreatePragmaFunctionInfo &) {
	Refuse("CREATE PRAGMA FUNCTION");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateCollation(CatalogTransaction, CreateCollationInfo &) {
	Refuse("CREATE COLLATION");
}
optional_ptr<CatalogEntry> XmlaSchemaEntry::CreateType(CatalogTransaction, CreateTypeInfo &) {
	Refuse("CREATE TYPE");
}
void XmlaSchemaEntry::Alter(CatalogTransaction, AlterInfo &) {
	Refuse("ALTER");
}
void XmlaSchemaEntry::DropEntry(ClientContext &, DropInfo &) {
	Refuse("DROP");
}

void XmlaSchemaEntry::LoadTables(ClientContext &context) {
	std::lock_guard<std::mutex> guard(load_lock_);
	if (loaded_) {
		return;
	}

	auto params = params_;
	const std::string model(name);

	xmla::Rowset tables;
	xmla::Rowset columns;
	try {
		auto session = OpenSession(context, params);
		tables = session->Discover("DBSCHEMA_TABLES", {}, model);
		columns = session->Discover("DBSCHEMA_COLUMNS", {}, model);
		session->Close();
	} catch (const xmla::XmlaError &error) {
		throw IOException("xmla: %s", error.what());
	}

	// Group the columns by table in one pass. DBSCHEMA_COLUMNS is the large
	// rowset — 1366 rows on a modest model — so walking it once per table would
	// be quadratic in the number of tables.
	case_insensitive_map_t<vector<std::string>> by_table;
	for (const auto &row : columns.rows) {
		const auto table = row.find("TABLE_NAME");
		const auto column = row.find("COLUMN_NAME");
		if (table == row.end() || column == row.end()) {
			continue;
		}
		by_table[table->second].push_back(column->second);
	}

	for (const auto &row : tables.rows) {
		const auto found = row.find("TABLE_NAME");
		if (found == row.end() || found->second.empty()) {
			continue;
		}
		const auto type = row.find("TABLE_TYPE");
		const std::string table_type = type == row.end() ? std::string() : type->second;

		// Only TABLE. What the other two are, measured against a live SQL Server
		// 2022 tabular model (research D13):
		//
		//   SCHEMA        123 rows in TABLE_SCHEMA='$SYSTEM' — the schema ROWSETS
		//                 (DBSCHEMA_CATALOGS, DMSCHEMA_MINING_COLUMNS, ...), not
		//                 user data. Listing them as tables filled SHOW ALL
		//                 TABLES with the server's own introspection surface.
		//   SYSTEM TABLE  'DimProduct' — the measure-group view, whose only
		//                 column is '__Count of DimProduct'.
		//   TABLE         '$DimProduct' — the dimension table, holding the real
		//                 columns.
		if (table_type != "TABLE") {
			continue;
		}

		// The '$' prefix is SSAS's internal dimension-table marker. The name DAX
		// uses — and therefore the name to present — is the unprefixed one:
		// `EVALUATE 'DimProduct'` works, `EVALUATE '$DimProduct'` is not what a
		// user would write.
		const std::string &internal_name = found->second;
		const std::string table_name =
			(!internal_name.empty() && internal_name[0] == '$') ? internal_name.substr(1) : internal_name;

		CreateTableInfo info(*this, Identifier(table_name));
		const auto cols = by_table.find(internal_name);
		size_t added = 0;
		if (cols != by_table.end()) {
			for (const auto &column_name : cols->second) {
				// The internal row surrogate. `EVALUATE` does not return it, so
				// advertising it would produce a column that is always NULL.
				if (column_name.compare(0, 10, "RowNumber-") == 0) {
					continue;
				}
				// VARCHAR throughout. XMLA reports a column's type in a separate
				// field and mapping it is T-041; guessing from a value would not
				// be honest.
				info.columns.AddColumn(ColumnDefinition(Identifier(column_name), LogicalType::VARCHAR));
				added++;
			}
		}
		if (added == 0) {
			// A table whose columns we cannot see still belongs in the listing —
			// SHOW ALL TABLES should show it — but cannot be selected from. One
			// placeholder keeps it describable rather than failing the schema.
			info.columns.AddColumn(ColumnDefinition("unknown", LogicalType::VARCHAR));
		}
		tables_[table_name] = make_uniq<XmlaTableEntry>(catalog, *this, info, params_, model, tabular_);
	}
	loaded_ = true;
}

void XmlaSchemaEntry::Scan(ClientContext &context, CatalogType type,
						   const std::function<void(CatalogEntry &)> &callback) {
	if (type != CatalogType::TABLE_ENTRY) {
		return;
	}
	LoadTables(context);
	std::lock_guard<std::mutex> guard(load_lock_);
	for (auto &entry : tables_) {
		callback(*entry.second);
	}
}

void XmlaSchemaEntry::Scan(CatalogType, const std::function<void(CatalogEntry &)> &) {
	// The context-free overload cannot reach the server, and returning nothing
	// is better than throwing: DuckDB calls it while listing metadata, and a
	// throw there would break unrelated queries.
}

optional_ptr<CatalogEntry> XmlaSchemaEntry::LookupEntry(CatalogTransaction transaction,
														const EntryLookupInfo &lookup_info) {
	if (lookup_info.GetCatalogType() != CatalogType::TABLE_ENTRY) {
		return nullptr;
	}
	if (!transaction.HasContext()) {
		return nullptr;
	}
	LoadTables(transaction.GetContext());
	std::lock_guard<std::mutex> guard(load_lock_);
	const auto found = tables_.find(lookup_info.GetEntryName());
	if (found == tables_.end()) {
		return nullptr;
	}
	return found->second.get();
}

}  // namespace duckdb
