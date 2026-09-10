#include "xmla_functions.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla_connection.hpp"

namespace duckdb {

namespace {

//! One request's worth of state: the rows, already fetched.
//!
//! The whole rowset is materialised at bind time rather than streamed. That is
//! deliberate for now and is not free: DBSCHEMA_COLUMNS on a modest model is
//! 1366 rows, which is nothing, but a large Execute could be. Streaming needs
//! the protocol layer to hand back a cursor rather than a Rowset, which is a
//! change below this file and belongs with the pushdown work, not here.
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

//! Translate the protocol layer's categories into DuckDB exceptions.
//!
//! The categories exist so a caller can act without parsing text, and that is
//! preserved here rather than collapsed: an authorization failure says check the
//! account's permissions, a connection failure says check host and firewall.
//! Every message is already scrubbed of identifying tokens before it arrives.
[[noreturn]] void Rethrow(const xmla::XmlaError &error) {
	throw IOException("xmla: %s", error.what());
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
		Rethrow(error);
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
		Rethrow(error);
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

	const idx_t remaining = bind_data.rowset.rows.size() - state.offset;
	const idx_t count = MinValue<idx_t>(STANDARD_VECTOR_SIZE, remaining);
	if (count == 0) {
		output.SetCardinality(0);
		return;
	}

	const bool no_columns = bind_data.rowset.columns.empty();
	for (idx_t row = 0; row < count; row++) {
		const auto &values = bind_data.rowset.rows[state.offset + row];
		if (no_columns) {
			output.SetValue(0, row, Value());
			continue;
		}
		for (idx_t col = 0; col < bind_data.rowset.columns.size(); col++) {
			const auto found = values.find(bind_data.rowset.columns[col]);
			if (found == values.end()) {
				// XMLA OMITS a null column from a row rather than sending it
				// empty, so an absent key is SQL NULL — distinct from the empty
				// string a self-closing element means.
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
