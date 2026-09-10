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
				   std::string ssas_catalog, bool tabular, bool columns_known);

	//! v2.0 makes GetColumns pure virtual, so the derived entry owns the column
	//! list rather than the base holding it.
	const ColumnList &GetColumns() const override {
		return columns_;
	}

	//! No `rowid`, and no row-id columns at all.
	//!
	//! TableCatalogEntry's default advertises COLUMN_IDENTIFIER_ROW_ID as a
	//! virtual BIGINT column. Two things went wrong with that here. `SELECT
	//! rowid FROM <ssas table>` bound and produced a column this extension
	//! cannot produce — there is no row identity in an XMLA rowset. And
	//! `count(*)`, which needs SOME column and asks LogicalGet::GetAnyColumn for
	//! one, was handed the row id: the scan then had a BIGINT output vector
	//! while every value it writes is a string, which DuckDB caught as
	//! "Expected vector of type VARCHAR, but found vector of type INT64" —
	//! found by running count(*) against a live instance, because nothing
	//! server-free reaches a scan.
	//!
	//! COLUMN_IDENTIFIER_EMPTY is offered instead. It is the placeholder
	//! `count(*)` actually wants: one column of no particular meaning, so no
	//! real column has to be transferred to count rows.
	virtual_column_map_t GetVirtualColumns() const override;
	vector<column_t> GetRowIdColumns() const override;

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
	//! False when DBSCHEMA_COLUMNS showed nothing for this table and the column
	//! list is the single `unknown` placeholder. A projection cannot be pushed
	//! down in that case: naming a column the server does not have turns a scan
	//! that returned something into a DAX error.
	bool columns_known() const {
		return columns_known_;
	}

private:
	ColumnList columns_;
	XmlaConnectionParams params_;
	std::string ssas_catalog_;
	//! Whether the model is tabular, which decides whether a row scan is
	//! possible at all: reading a table's rows needs `EVALUATE '<name>'`, and
	//! DAX is not available on a multidimensional model.
	bool tabular_;
	bool columns_known_;
};

}  // namespace duckdb
