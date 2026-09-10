#include "catalog/xmla_table_entry.hpp"

#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "xmla/dax.hpp"
#include "xmla/errors.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

namespace {

//! Bind data holds only PARAMETERS and the pushed-down DAX. No rows.
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
struct XmlaScanBindData : public TableFunctionData {
	XmlaConnectionParams params;
	std::string ssas_catalog;
	std::string table_name;
	//! Every column the catalog advertised, in catalog order. `column_ids`
	//! indexes into this.
	vector<std::string> columns;
	bool columns_known = false;
};

struct XmlaScanState : public GlobalTableFunctionState {
	// DECLARATION ORDER MATTERS. Members are destroyed in reverse, and the
	// cursor borrows the session — so the session is declared first so that it
	// outlives the cursor that abandons it.
	std::unique_ptr<xmla::Session> session;
	std::unique_ptr<xmla::RowCursor> cursor;

	//! Which output column each discovered column belongs to. Lives in the
	//! protocol layer so it can be tested without DuckDB — the derivation it
	//! replaced could not be, and was written wrong twice.
	xmla::ColumnMap columns;
	//! Reused across rows so the per-row cells are not reallocated.
	std::vector<xmla::Cell> row;
	bool exhausted = false;
};

//===--------------------------------------------------------------------===//
// Why there is no filter pushdown here
//
// It was written, and the live instance refused it. `WHERE ProductKey = '477'`
// rendered as `FILTER('FactInternetSales', 'FactInternetSales'[ProductKey] =
// "477")` and came back:
//
//   DAX comparison operations do not support comparing values of type Integer
//   with values of type Text. Consider using the VALUE or FORMAT function to
//   convert one of the values.
//
// Every column this extension presents is VARCHAR — the real type mapping is
// T-041 — so a rendered constant is always a DAX text literal, and DAX refuses
// the comparison outright against a numeric column rather than coercing. It is a
// hard error at query time, so the failure is loud rather than silent, which
// makes it worse in practice: a WHERE clause that works today would stop working
// the moment it named a numeric column.
//
// Knowing the column's type would settle it, and there is no non-admin way to
// learn it (both measured against SQL Server 2022 Analysis Services, 2026-09):
//
//   * DBSCHEMA_COLUMNS reports DATA_TYPE = 130 (DBTYPE_WSTR) for EVERY column of
//     a tabular model, including the one DAX calls Integer. It cannot tell them
//     apart. This also constrains T-041.
//   * TMSCHEMA_COLUMNS, which does carry ExplicitDataType, is refused:
//     "needs to be an administrator to read the metadata of the database".
//
// A type-agnostic rendering does not exist either. CONVERT(c, STRING) and
// CONTAINSSTRING both push the comparison through DAX's own number-to-text
// formatting, which need not match the rendering XMLA puts in the rowset — and a
// mismatch DROPS rows DuckDB would have kept, which is the one failure mode that
// is silent. `IFERROR` does not help: the message above is reported with a query
// position, so it is raised when the expression is analysed, not per row.
//
// So the WHERE clause stays where DuckDB applies it, and the transfer reduction
// comes from the projection instead. What would unblock this is T-041 learning
// the real types from DISCOVER_CSDL_METADATA (which a reader can call) rather
// than from either schema rowset.
//===--------------------------------------------------------------------===//

unique_ptr<GlobalTableFunctionState> ScanInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<XmlaScanBindData>();
	auto state = make_uniq<XmlaScanState>();

	// The projection, in the order the executor expects the output columns.
	//
	// A column id with no counterpart on the server — a row id, or the EMPTY
	// placeholder `count(*)` asks for — is skipped here and left NULL in the
	// output. Its OUTPUT POSITION is carried explicitly rather than inferred
	// from list order: the two diverge at exactly that skip, and inferring it
	// mapped the first real column afterwards to output 0 instead of 1, which
	// shows up as a requested column arriving all NULL.
	vector<std::string> wanted;
	vector<std::pair<std::string, int64_t>> requested;
	for (idx_t out = 0; out < input.column_ids.size(); out++) {
		const auto column_id = input.column_ids[out];
		if (column_id >= bind_data.columns.size()) {
			continue;
		}
		const std::string &name = bind_data.columns[column_id];
		wanted.push_back(name);
		requested.emplace_back(name, static_cast<int64_t>(out));
	}
	// Which name forms a column may come back under, and which output each maps
	// to, is xmla::ColumnMap's business — see its comment for why that is in the
	// protocol layer and not here.
	state->columns = xmla::ColumnMap(bind_data.table_name, requested);

	// `count(*)` asks for no real column at all — it takes the EMPTY virtual
	// column instead. The server still has to send something, so ONE column is
	// projected and then ignored: nothing maps it to an output position, so
	// every cell it produces is dropped and only the row count survives. Without
	// this the fallback is `EVALUATE 'T'`, and counting rows would transfer the
	// whole table.
	if (wanted.empty() && bind_data.columns_known && !bind_data.columns.empty()) {
		wanted.push_back(bind_data.columns[0]);
	}

	// Composing the statement — and deciding whether a projection is safe and
	// worth sending at all — is xmla::dax's business, and it is tested there.
	const std::string dax = xmla::dax::Evaluate(bind_data.table_name, wanted, bind_data.columns.size());
	try {
		state->session = OpenSession(context, bind_data.params);
		state->cursor = state->session->ExecuteCursor(dax, bind_data.ssas_catalog);
	} catch (const xmla::XmlaError &error) {
		RethrowXmlaError(error);
	}
	return std::move(state);
}

void ScanExecute(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<XmlaScanState>();
	const idx_t columns = output.ColumnCount();

	if (state.exhausted) {
		output.SetChildCardinality(0);
		return;
	}

	// Every value this scan produces is a string, so a column that is not
	// VARCHAR is one this scan does not fill: the EMPTY placeholder `count(*)`
	// asks for, or any virtual column a later DuckDB adds. Writing a string_t
	// into it is not a wrong answer, it is a type-confused write into someone
	// else's memory — DuckDB's own check caught it, and the check is not
	// guaranteed to be there in a release build.
	vector<string_t *> vectors(columns, nullptr);
	vector<ValidityMask *> validities(columns, nullptr);
	for (idx_t col = 0; col < columns; col++) {
		validities[col] = &FlatVector::ValidityMutable(output.data[col]);
		if (output.data[col].GetType().id() == LogicalTypeId::VARCHAR) {
			vectors[col] = FlatVector::GetDataMutable<string_t>(output.data[col]);
		}
	}

	idx_t count = 0;
	try {
		while (count < STANDARD_VECTOR_SIZE) {
			if (!state.cursor->Next(state.row)) {
				state.exhausted = true;
				break;
			}
			// The cursor's column list GROWS as rows arrive: a column that was
			// null in every row so far has not been seen yet. So the mapping is
			// extended here rather than resolved once — and never derived from
			// the first row, which is the shape of the all-NULL bug.
			state.columns.Extend(state.cursor->columns());

			// Start every value NULL. XMLA OMITS a null column from a row rather
			// than sending it empty, so absence IS null — distinct from the empty
			// string a self-closing element means.
			for (idx_t col = 0; col < columns; col++) {
				validities[col]->SetInvalid(count);
			}
			for (const auto &cell : state.row) {
				const int64_t out = state.columns.OutputFor(cell.column);
				if (out < 0 || static_cast<idx_t>(out) >= columns) {
					continue;
				}
				const idx_t col = static_cast<idx_t>(out);
				if (!vectors[col]) {
					continue;
				}
				validities[col]->SetValid(count);
				vectors[col][count] = StringVector::AddString(output.data[col], cell.value.data(), cell.value.size());
			}
			count++;
		}
	} catch (const xmla::XmlaError &error) {
		RethrowXmlaError(error);
	}

	if (state.exhausted) {
		// Drained, so the connection is at a record boundary and can be closed
		// properly. A cursor destroyed BEFORE this abandons it instead, which is
		// what makes an interrupted scan cheap.
		state.cursor.reset();
		if (state.session) {
			state.session->Close();
		}
	}
	output.SetChildCardinality(count);
}

}  // namespace

XmlaTableEntry::XmlaTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, CreateTableInfo &info,
							   XmlaConnectionParams params, std::string ssas_catalog, bool tabular, bool columns_known)
	: TableCatalogEntry(catalog, schema, info),
	  columns_(info.columns.Copy()),
	  params_(std::move(params)),
	  ssas_catalog_(std::move(ssas_catalog)),
	  tabular_(tabular),
	  columns_known_(columns_known) {}

virtual_column_map_t XmlaTableEntry::GetVirtualColumns() const {
	virtual_column_map_t virtual_columns;
	virtual_columns.insert(make_pair(COLUMN_IDENTIFIER_EMPTY, TableColumn("", LogicalType::BOOLEAN)));
	return virtual_columns;
}

vector<column_t> XmlaTableEntry::GetRowIdColumns() const {
	// None. The base class returns COLUMN_IDENTIFIER_ROW_ID, which this table
	// has no way to produce.
	return vector<column_t>();
}

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

	// PARAMETERS ONLY. Nothing here contacts the server: the request goes out in
	// ScanInit, so EXPLAIN costs nothing and a re-executed prepared statement
	// re-reads rather than replaying a bind-time snapshot.
	auto result = make_uniq<XmlaScanBindData>();
	result->params = params_;
	result->ssas_catalog = ssas_catalog_;
	result->table_name = std::string(name);
	result->columns_known = columns_known_;
	for (auto &column : GetColumns().Logical()) {
		result->columns.push_back(column.Name().GetIdentifierName());
	}

	TableFunction scan("xmla_table_scan", {}, ScanExecute, nullptr, ScanInit);
	// The projection reaches the server as a SELECTCOLUMNS list, so a narrow
	// SELECT over a wide table transfers narrow.
	scan.projection_pushdown = true;
	// No filter pushdown, in either form. See the block comment above ScanInit
	// for the measurement that decided it.
	scan.filter_pushdown = false;
	bind_data = std::move(result);
	return scan;
}

}  // namespace duckdb
