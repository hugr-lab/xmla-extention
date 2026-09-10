#include "xmla_functions.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

namespace {

//! One request's worth of state: the rows, already fetched.
//!
//! These two functions materialise the whole rowset ON PURPOSE, where the table
//! scan (catalog/xmla_table_entry.cpp) streams through a RowCursor. The reason
//! is the return shape: both bind their column list from the rowset's column
//! UNION, and the union is not known until the last row has been seen — XMLA
//! omits a null column from a row entirely, so a column that is null everywhere
//! but the final row appears only there. A streaming bind would have to guess a
//! schema, and guessing it from the first row is precisely the bug that made a
//! whole scan return NULL, twice.
//!
//! The scan does not have that problem because it knows its columns from the
//! catalog before it asks for anything.
struct XmlaBindData : public TableFunctionData {
	xmla::Rowset rowset;
};

struct XmlaGlobalState : public GlobalTableFunctionState {
	idx_t offset = 0;
};

//! Columns come from the rowset's own union of column names, in first-seen
//! order, and are all VARCHAR.
//!
//! VARCHAR because the protocol layer deliberately returns strings: XMLA reports
//! a column's type in a separate rowset, and mapping it belongs one layer up
//! (T-041). Returning VARCHAR now is honest; guessing a type from the value
//! would not be.
void DescribeRowset(const xmla::Rowset &rowset, vector<LogicalType> &types, vector<Identifier> &names) {
	if (rowset.columns.empty()) {
		// An empty rowset is a MEANINGFUL answer — "no catalogs visible to this
		// account" — so it must produce a valid relation rather than an error.
		// A single column keeps it describable.
		names.emplace_back("result");
		types.emplace_back(LogicalType::VARCHAR);
		return;
	}
	for (const auto &column : rowset.columns) {
		// Identifier from a runtime string is EXPLICIT by design in v2.0: it
		// carries case-insensitive semantics, so promoting a server-supplied
		// column name has to be a deliberate choice. It is: XMLA rowset column
		// names are SQL identifiers.
		names.push_back(Identifier(column));
		types.emplace_back(LogicalType::VARCHAR);
	}
}

XmlaConnectionParams ParamsFrom(TableFunctionBindInput &input) {
	auto params = XmlaConnectionParams::FromString(StringValue::Get(input.inputs[0]));
	for (const auto &named : input.named_parameters) {
		const auto key = StringUtil::Lower(named.first.GetIdentifierName());
		if (key == "catalog") {
			params.catalog = StringValue::Get(named.second);
		} else if (key == "secret") {
			params.secret_name = StringValue::Get(named.second);
		}
	}
	return params;
}

unique_ptr<FunctionData> DiscoverBind(ClientContext &context, TableFunctionBindInput &input,
									  vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<XmlaBindData>();
	auto params = ParamsFrom(input);
	const auto request_type = StringValue::Get(input.inputs[1]);

	std::map<std::string, std::string> restrictions;
	for (const auto &named : input.named_parameters) {
		// Identifier compares case-insensitively, which is what we want here.
		if (!(named.first == Identifier("restrictions"))) {
			continue;
		}
		// A MAP, so the names are data rather than SQL text. envelopes validates
		// each name against the XMLA rowset column shape and REJECTS anything
		// else — an element name cannot be made safe by escaping.
		const auto &keys = MapValue::GetChildren(named.second);
		for (const auto &entry : keys) {
			const auto &kv = StructValue::GetChildren(entry);
			restrictions[StringValue::Get(kv[0])] = StringValue::Get(kv[1]);
		}
	}

	try {
		auto session = OpenSession(context, params);
		result->rowset = session->Discover(request_type, restrictions, params.catalog);
		session->Close();
	} catch (const xmla::XmlaError &error) {
		RethrowXmlaError(error);
	}

	DescribeRowset(result->rowset, return_types, names);
	return std::move(result);
}

unique_ptr<FunctionData> ExecuteBind(ClientContext &context, TableFunctionBindInput &input,
									 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<XmlaBindData>();
	auto params = ParamsFrom(input);
	const auto statement = StringValue::Get(input.inputs[1]);

	// The read-only guard runs BEFORE any connection is opened.
	//
	// It used to run inside Session::Execute, which is after the socket, the
	// handshake and the sealing context — so `UPDATE CUBE ...` against an
	// unreachable host reported a connection failure, and against a reachable one
	// spent a full authenticated round trip to reach a verdict that depends on
	// nothing but the string. It is also a BinderException rather than an
	// IOException, because whether a statement is a query is a static property of
	// the query, not an I/O outcome.
	try {
		xmla::envelopes::RejectIfMutating(statement);
	} catch (const xmla::XmlaError &error) {
		throw BinderException("xmla: %s", error.what());
	}

	try {
		auto session = OpenSession(context, params);
		// Read-only by VALIDATION, not by construction: XMLA's <Statement>
		// carries the whole command surface. Session::Execute checks again — the
		// guard belongs with the envelope, and this layer must not be the only
		// thing standing between a caller and a writeback. Neither check is
		// sufficient on its own: grant the account read-only permissions.
		result->rowset = session->Execute(statement, params.catalog);
		session->Close();
	} catch (const xmla::XmlaError &error) {
		RethrowXmlaError(error);
	}

	DescribeRowset(result->rowset, return_types, names);
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> InitGlobal(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<XmlaGlobalState>();
}

void Scan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<XmlaBindData>();
	auto &state = data.global_state->Cast<XmlaGlobalState>();
	const auto &rowset = bind_data.rowset;

	const idx_t remaining = rowset.size() - state.offset;
	const idx_t count = MinValue<idx_t>(STANDARD_VECTOR_SIZE, remaining);
	if (count == 0) {
		output.SetChildCardinality(0);
		return;
	}

	// An empty rowset still describes one column, so it can still be selected
	// from; every value in it is NULL.
	if (rowset.columns.empty()) {
		auto &validity = FlatVector::ValidityMutable(output.data[0]);
		for (idx_t row = 0; row < count; row++) {
			validity.SetInvalid(row);
		}
		state.offset += count;
		output.SetChildCardinality(count);
		return;
	}

	// A cell carries its own column INDEX, and DescribeRowset advertised the
	// columns in exactly rowset.columns order — so a cell's column is already
	// the output column and there is no name lookup at all. The map-per-row this
	// replaced hashed a column name once per value.
	const idx_t columns = MinValue<idx_t>(output.ColumnCount(), rowset.columns.size());
	vector<string_t *> vectors(columns, nullptr);
	vector<ValidityMask *> validities(columns, nullptr);
	for (idx_t col = 0; col < columns; col++) {
		vectors[col] = FlatVector::GetDataMutable<string_t>(output.data[col]);
		validities[col] = &FlatVector::ValidityMutable(output.data[col]);
	}

	for (idx_t row = 0; row < count; row++) {
		// Start NULL and fill only what the row carries. XMLA OMITS a null column
		// from a row rather than sending it empty, so absence IS null — distinct
		// from the empty string a self-closing element means.
		for (idx_t col = 0; col < columns; col++) {
			validities[col]->SetInvalid(row);
		}
		const auto cells = rowset.Row(state.offset + row);
		for (const auto *cell = cells.begin(); cell != cells.end(); ++cell) {
			if (cell->column >= columns) {
				continue;
			}
			const idx_t col = cell->column;
			validities[col]->SetValid(row);
			vectors[col][row] = StringVector::AddString(output.data[col], cell->value.data(), cell->value.size());
		}
	}
	state.offset += count;
	output.SetChildCardinality(count);
}

}  // namespace

void RegisterXmlaFunctions(ExtensionLoader &loader) {
	TableFunction discover("xmla_discover", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Scan, DiscoverBind,
						   InitGlobal);
	discover.named_parameters["catalog"] = LogicalType::VARCHAR;
	discover.named_parameters["secret"] = LogicalType::VARCHAR;
	discover.named_parameters["restrictions"] = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	loader.RegisterFunction(discover);

	TableFunction execute("xmla_execute", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Scan, ExecuteBind, InitGlobal);
	execute.named_parameters["catalog"] = LogicalType::VARCHAR;
	execute.named_parameters["secret"] = LogicalType::VARCHAR;
	loader.RegisterFunction(execute);
}

}  // namespace duckdb
