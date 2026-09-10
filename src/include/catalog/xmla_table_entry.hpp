//===----------------------------------------------------------------------===//
// One SSAS table (or cube-equivalent) as a DuckDB table.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/storage/table_storage_info.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

class XmlaTableEntry : public TableCatalogEntry {
public:
	XmlaTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, CreateTableInfo &info, XmlaConnectionParams params,
				   std::string ssas_catalog, bool tabular);

	//! v2.0 makes GetColumns pure virtual, so the derived entry owns the column
	//! list rather than the base holding it.
	const ColumnList &GetColumns() const override {
		return columns_;
	}

	unique_ptr<BaseStatistics> GetStatistics(ClientContext &context, column_t column_id) override;
	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override;
	TableStorageInfo GetStorageInfo(ClientContext &context) override;

	const XmlaConnectionParams &params() const {
		return params_;
	}
	const std::string &ssas_catalog() const {
		return ssas_catalog_;
	}
	bool tabular() const {
		return tabular_;
	}

private:
	ColumnList columns_;
	XmlaConnectionParams params_;
	std::string ssas_catalog_;
	//! Whether the model is tabular, which decides whether a row scan is
	//! possible at all: reading a table's rows needs `EVALUATE '<name>'`, and
	//! DAX is not available on a multidimensional model.
	bool tabular_;
};

}  // namespace duckdb
