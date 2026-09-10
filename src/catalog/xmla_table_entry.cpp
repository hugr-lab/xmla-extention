#include "catalog/xmla_table_entry.hpp"

#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "xmla/errors.hpp"

namespace duckdb {

namespace {

//! Bind data holds only PARAMETERS. No rows.
//!
//! The query used to be issued in GetScanFunction — that is, during BINDING —
//! with the whole result retained in the bind data. Three things followed, none
//! of them intended:
//!
//!   * `EXPLAIN SELECT * FROM aw.m.t` contacted the server and downloaded the
//!     entire table just to produce a plan.
//!   * a plan bound once and executed repeatedly (PREPARE/EXECUTE) served the
//!     snapshot taken at bind time, for the life of the statement.
//!   * the rows were fetched before the executor could have applied anything.
//!
//! Fetching in the global init fixes the first two outright. The third is limit
//! and filter pushdown, which is T-042 and needs the protocol layer to hand back
//! a cursor rather than a whole Rowset; until then a scan does transfer the
//! table, which is why this is a scan and not a pushdown.
struct XmlaScanBindData : public TableFunctionData {
	XmlaConnectionParams params;
	std::string ssas_catalog;
	std::string table_name;
	//! What the catalog advertised, in order. The plan is already bound to these.
	vector<std::string> columns;
};

struct XmlaScanState : public GlobalTableFunctionState {
	xmla::Rowset rowset;
	//! The key to look each advertised column up by in the rowset the server
	//! returned. NOT the column name: `EVALUATE 'DimProduct'` names its columns
	//! `DimProduct[ProductKey]`, so a bare "ProductKey" lookup misses every row
	//! and the scan returns all-NULL — which is what it did.
	vector<std::string> lookup_keys;
	idx_t offset = 0;
};

unique_ptr<GlobalTableFunctionState> ScanInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<XmlaScanBindData>();
	auto state = make_uniq<XmlaScanState>();

	try {
		auto session = OpenSession(context, bind_data.params);
		// A quoted single-table EVALUATE. The table name is a DAX identifier, so
		// it is quoted rather than escaped; a single quote inside it is doubled,
		// which is DAX's own escape.
		std::string quoted;
		for (char c : bind_data.table_name) {
			if (c == '\'') {
				quoted.push_back('\'');
			}
			quoted.push_back(c);
		}
		state->rowset = session->Execute("EVALUATE '" + quoted + "'", bind_data.ssas_catalog);
		session->Close();
	} catch (const xmla::XmlaError &error) {
		throw IOException("xmla: %s", error.what());
	}

	// The probe uses the rowset's COLUMN UNION, never a single row.
	//
	// XMLA omits a NULL column from a row entirely — that is precisely why
	// Rowset carries a separate `columns` union, and why ScanExecute treats an
	// absent key as NULL. Probing rows[0] reintroduced the all-NULL bug it was
	// written to fix, narrowed to "row 0 happens to be NULL in this column": the
	// qualified key is absent from row 0, the code falls back to the bare name,
	// and the bare name then misses on every row.
	const auto has_column = [&state](const std::string &key) {
		for (const auto &column : state->rowset.columns) {
			if (column == key) {
				return true;
			}
		}
		return false;
	};
	for (const auto &bare : bind_data.columns) {
		const std::string qualified = bind_data.table_name + "[" + bare + "]";
		state->lookup_keys.push_back(has_column(qualified) ? qualified : bare);
	}
	return std::move(state);
}

void ScanExecute(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<XmlaScanState>();

	const idx_t remaining = state.rowset.rows.size() - state.offset;
	const idx_t count = MinValue<idx_t>(STANDARD_VECTOR_SIZE, remaining);
	if (count == 0) {
		output.SetCardinality(0);
		return;
	}
	for (idx_t row = 0; row < count; row++) {
		const auto &values = state.rowset.rows[state.offset + row];
		for (idx_t col = 0; col < state.lookup_keys.size(); col++) {
			const auto found = values.find(state.lookup_keys[col]);
			if (found == values.end()) {
				// XMLA omits a null column rather than sending it empty.
				output.SetValue(col, row, Value());
			} else {
				output.SetValue(col, row, Value(found->second));
			}
		}
	}
	state.offset += count;
	output.SetCardinality(count);
}

}  // namespace

XmlaTableEntry::XmlaTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, CreateTableInfo &info,
							   XmlaConnectionParams params, std::string ssas_catalog, bool tabular)
	: TableCatalogEntry(catalog, schema, info),
	  columns_(info.columns.Copy()),
	  params_(std::move(params)),
	  ssas_catalog_(std::move(ssas_catalog)),
	  tabular_(tabular) {}

unique_ptr<BaseStatistics> XmlaTableEntry::GetStatistics(ClientContext &, column_t) {
	// None. DBSCHEMA_TABLES does not carry a row count, and inventing one would
	// mislead the optimiser rather than help it.
	return nullptr;
}

TableStorageInfo XmlaTableEntry::GetStorageInfo(ClientContext &) {
	TableStorageInfo info;
	// Deliberately left without a cardinality: unknown is the honest answer, and
	// a guess would change plans.
	return info;
}

TableFunction XmlaTableEntry::GetScanFunction(ClientContext &, unique_ptr<FunctionData> &bind_data) {
	if (!tabular_) {
		// Reading a table's ROWS needs `EVALUATE '<name>'`, which is DAX, and DAX
		// is not available on a multidimensional model — its data is reached with
		// MDX over cubes, dimensions and measure groups, which is a different
		// shape entirely and not something to fake.
		//
		// The metadata still works: this catalog's schemas and tables list fine,
		// and xmla_execute carries MDX for anyone who wants to write it.
		throw NotImplementedException(
			"xmla: '%s' is in a multidimensional model, whose rows cannot be read as a table. "
			"Multidimensional data is queried with MDX — use xmla_execute() — while a tabular "
			"model's tables support SELECT directly.",
			name);
	}

	// PARAMETERS ONLY. Nothing here contacts the server: the fetch happens in
	// ScanInit, so EXPLAIN costs nothing and a re-executed prepared statement
	// re-reads rather than replaying a bind-time snapshot.
	auto result = make_uniq<XmlaScanBindData>();
	result->params = params_;
	result->ssas_catalog = ssas_catalog_;
	result->table_name = std::string(name);
	for (auto &column : GetColumns().Logical()) {
		result->columns.push_back(column.Name().GetIdentifierName());
	}

	TableFunction scan("xmla_table_scan", {}, ScanExecute, nullptr, ScanInit);
	scan.projection_pushdown = false;
	bind_data = std::move(result);
	return scan;
}

}  // namespace duckdb
