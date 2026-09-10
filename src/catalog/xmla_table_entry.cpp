#include "catalog/xmla_table_entry.hpp"

#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "xmla/errors.hpp"

namespace duckdb {

namespace {

struct XmlaScanBindData : public TableFunctionData {
	xmla::Rowset rowset;
	//! The key to look each advertised column up by, in the rowset the server
	//! returned. NOT the column name: `EVALUATE 'DimProduct'` names its columns
	//! `DimProduct[ProductKey]`, so a bare "ProductKey" lookup misses every row
	//! and the scan returns all-NULL — which is what it did.
	vector<std::string> lookup_keys;
};

struct XmlaScanState : public GlobalTableFunctionState {
	idx_t offset = 0;
};

unique_ptr<GlobalTableFunctionState> ScanInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<XmlaScanState>();
}

void ScanExecute(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<XmlaScanBindData>();
	auto &state = data.global_state->Cast<XmlaScanState>();

	const idx_t remaining = bind_data.rowset.rows.size() - state.offset;
	const idx_t count = MinValue<idx_t>(STANDARD_VECTOR_SIZE, remaining);
	if (count == 0) {
		output.SetCardinality(0);
		return;
	}
	for (idx_t row = 0; row < count; row++) {
		const auto &values = bind_data.rowset.rows[state.offset + row];
		for (idx_t col = 0; col < bind_data.lookup_keys.size(); col++) {
			const auto found = values.find(bind_data.lookup_keys[col]);
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

TableFunction XmlaTableEntry::GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) {
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

	auto result = make_uniq<XmlaScanBindData>();
	try {
		auto session = OpenSession(context, params_);
		// A quoted single-table EVALUATE. The table name is a DAX identifier, so
		// it is quoted rather than escaped; a name containing a single quote is
		// doubled, which is DAX's own escape.
		std::string quoted;
		for (char c : std::string(name)) {
			if (c == '\'') {
				quoted.push_back('\'');
			}
			quoted.push_back(c);
		}
		result->rowset = session->Execute("EVALUATE '" + quoted + "'", ssas_catalog_);
		session->Close();
	} catch (const xmla::XmlaError &error) {
		throw IOException("xmla: %s", error.what());
	}

	// The scan must produce the columns the CATALOG advertised, in that order,
	// whatever the server happens to return — a plan is already bound to them.
	//
	// DAX qualifies its result columns as `<table>[<column>]`, so that is tried
	// first and the bare name second. The fallback matters: DISCOVER and DBSCHEMA
	// rowsets return bare names, and a future scan built on one of those would
	// otherwise silently produce NULLs.
	for (auto &column : GetColumns().Logical()) {
		const std::string bare = column.Name().GetIdentifierName();
		const std::string qualified = std::string(name) + "[" + bare + "]";
		result->lookup_keys.push_back(result->rowset.rows.empty()				? bare
									  : result->rowset.rows[0].count(qualified) ? qualified
																				: bare);
	}

	TableFunction scan("xmla_table_scan", {}, ScanExecute, nullptr, ScanInit);
	scan.projection_pushdown = false;
	bind_data = std::move(result);
	return scan;
}

}  // namespace duckdb
