//===----------------------------------------------------------------------===//
// An attached Analysis Services instance as a DuckDB catalog.
//
//   ATTACH 'host=<host> port=<port>' AS aw (TYPE xmla);
//
// Schemas are the instance's catalogs (models/databases); tables are their
// tables. That mapping is what makes SHOW ALL TABLES and DESCRIBE work without
// this extension implementing either.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "xmla_connection.hpp"

#include <mutex>

namespace duckdb {

class XmlaCatalog : public Catalog {
public:
	XmlaCatalog(AttachedDatabase &db, XmlaConnectionParams params);
	~XmlaCatalog() noexcept override;

	void Initialize(bool load_builtin) override;
	string GetCatalogType() override;

	optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction transaction, CreateSchemaInfo &info) override;
	void DropSchema(ClientContext &context, DropInfo &info) override;
	void ScanSchemas(ClientContext &context, std::function<void(SchemaCatalogEntry &)> callback) override;
	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction transaction, const EntryLookupInfo &lookup_info,
												  OnEntryNotFound if_not_found) override;

	DatabaseSize GetDatabaseSize(ClientContext &context) override;
	bool InMemory() override;
	string GetDBPath() override;

	//! T-037. Refuse rather than translate: a DuckDB catalog that does not
	//! override these gets DEFAULTS, and a default that plans an INSERT would
	//! make the read-only guarantee depend on DuckDB's behaviour rather than on
	//! this extension containing no path to a write.
	PhysicalOperator &PlanInsert(ClientContext &context, PhysicalPlanGenerator &planner, LogicalInsert &op,
								 optional_ptr<PhysicalOperator> plan) override;
	PhysicalOperator &PlanCreateTableAs(ClientContext &context, PhysicalPlanGenerator &planner, LogicalCreateTable &op,
										PhysicalOperator &plan) override;
	PhysicalOperator &PlanDelete(ClientContext &context, PhysicalPlanGenerator &planner, LogicalDelete &op,
								 PhysicalOperator &plan) override;
	PhysicalOperator &PlanUpdate(ClientContext &context, PhysicalPlanGenerator &planner, LogicalUpdate &op,
								 PhysicalOperator &plan) override;
	unique_ptr<LogicalOperator> BindCreateIndex(Binder &binder, CreateStatement &stmt, TableCatalogEntry &table,
												unique_ptr<LogicalOperator> plan) override;

	const XmlaConnectionParams &params() const {
		return params_;
	}

private:
	//! Fetch DBSCHEMA_CATALOGS once, on first use.
	void LoadSchemas(ClientContext &context);

	XmlaConnectionParams params_;
	std::mutex load_lock_;
	bool loaded_ = false;
	case_insensitive_map_t<unique_ptr<CatalogEntry>> schemas_;
};

}  // namespace duckdb
