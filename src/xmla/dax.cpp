#include "xmla/dax.hpp"

#include "xmla/errors.hpp"

namespace xmla {
namespace dax {

bool SafeName(const std::string &name) {
	if (name.empty()) {
		return false;
	}
	for (const char c : name) {
		const unsigned char byte = static_cast<unsigned char>(c);
		if (byte < 0x20 || byte == 0x7F) {
			// Control characters, including the newlines a DAX comment could
			// hide behind.
			return false;
		}
		if (c == '[' || c == ']' || c == '\'' || c == '"') {
			return false;
		}
	}
	return true;
}

std::string Table(const std::string &table) {
	return "'" + table + "'";
}

std::string Column(const std::string &table, const std::string &column) {
	return Table(table) + "[" + column + "]";
}

std::string StringLiteral(const std::string &value) {
	std::string out = "\"";
	for (const char c : value) {
		if (c == '"') {
			out.push_back('"');
		}
		out.push_back(c);
	}
	out.push_back('"');
	return out;
}

std::string Evaluate(const std::string &table, const std::vector<std::string> &wanted, size_t total_columns,
					 bool columns_known) {
	if (!SafeName(table)) {
		// REFUSE. There is nothing safe to compose around an unsafe table name:
		// the plain form quotes it too, so returning `EVALUATE '<name>'` would
		// emit the rejected string verbatim into a quoted context and leave the
		// operator with a DAX syntax error they cannot attribute to anything.
		throw ProtocolError(
			"the table name the server reported cannot be used in a query; "
			"it contains a quote, a bracket or a control character");
	}
	const std::string source = Table(table);

	bool narrows = columns_known && !wanted.empty() && wanted.size() < total_columns;
	for (const auto &column : wanted) {
		if (!SafeName(column)) {
			// ONE unsafe name disables the whole projection rather than part of
			// it: a partial projection returns fewer columns than the caller is
			// expecting, which is a wrong answer rather than a slow one.
			narrows = false;
			break;
		}
	}
	if (!narrows) {
		return "EVALUATE " + source;
	}

	std::string projection = "SELECTCOLUMNS(" + source;
	for (const auto &column : wanted) {
		projection += ", " + StringLiteral(column) + ", " + Column(table, column);
	}
	projection += ")";
	return "EVALUATE " + projection;
}

}  // namespace dax
}  // namespace xmla
