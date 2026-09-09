//===----------------------------------------------------------------------===//
// Parse an XMLA response into rows, and surface a SOAP fault as one.
//
// Values stay STRINGS. Interpreting them is the DuckDB type mapping's business
// one layer up; doing it here would put a type system in the protocol layer.
//
// This is a scanner, not a general XML parser. It answers two questions - "what
// rows are in here" and "is this a fault" - and it consumes bytes from a remote
// peer, so it is written to terminate and stay in bounds on any input rather
// than to be complete. It is a fuzz target (T-063).
//===----------------------------------------------------------------------===//
#pragma once

#include <map>
#include <string>
#include <vector>

namespace xmla {

struct Rowset {
	//! Column names in first-seen order. XMLA omits null columns from a row, so
	//! the union across rows is the schema and no single row need carry it.
	std::vector<std::string> columns;
	std::vector<std::map<std::string, std::string>> rows;

	size_t size() const {
		return rows.size();
	}
	bool empty() const {
		return rows.empty();
	}
};

struct Fault {
	bool present = false;
	std::string code;
	std::string message;
};

//! Parse an XMLA rowset response. Matches on LOCAL element names, so the
//! default `...:rowset` namespace needs no special handling.
Rowset ParseRowset(const std::string &text);

//! Return the SOAP fault carried by a response, if any.
Fault FindFault(const std::string &text);

//! Pull one element's text out of a document by local name. Used for SessionId
//! and for the handshake's security token.
bool FindElementText(const std::string &text, const std::string &local_name, std::string &out);

//! Pull an attribute value off the first element with the given local name.
bool FindAttribute(const std::string &text, const std::string &local_name, const std::string &attribute,
				   std::string &out);

}  // namespace xmla
