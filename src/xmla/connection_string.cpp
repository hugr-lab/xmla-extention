#include "xmla/connection_string.hpp"

#include "xmla/errors.hpp"

#include <vector>

namespace xmla {

namespace {

bool IsKeyStart(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool IsKeyChar(char c) {
	return IsKeyStart(c) || (c >= '0' && c <= '9');
}

bool IsSpace(char c) {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string Trim(const std::string &in) {
	size_t first = 0;
	while (first < in.size() && IsSpace(in[first])) {
		first++;
	}
	size_t last = in.size();
	while (last > first && IsSpace(in[last - 1])) {
		last--;
	}
	return in.substr(first, last - first);
}

std::string LowerAscii(const std::string &in) {
	std::string out = in;
	for (auto &c : out) {
		if (c >= 'A' && c <= 'Z') {
			c = static_cast<char>(c - 'A' + 'a');
		}
	}
	return out;
}

//! Is there a `key=` token starting at `i`, at a token boundary?
bool KeyTokenAt(const std::string &s, size_t i, size_t &key_end) {
	if (i >= s.size() || !IsKeyStart(s[i])) {
		return false;
	}
	if (i > 0 && !IsSpace(s[i - 1]) && s[i - 1] != ';') {
		return false;
	}
	size_t j = i;
	while (j < s.size() && IsKeyChar(s[j])) {
		j++;
	}
	if (j >= s.size() || s[j] != '=') {
		return false;
	}
	key_end = j;
	return true;
}

}  // namespace

std::map<std::string, std::string> ParseConnectionString(const std::string &connection) {
	std::map<std::string, std::string> options;

	size_t i = 0;
	while (i < connection.size()) {
		while (i < connection.size() && (IsSpace(connection[i]) || connection[i] == ';')) {
			i++;
		}
		if (i >= connection.size()) {
			break;
		}

		size_t key_end = 0;
		if (!KeyTokenAt(connection, i, key_end)) {
			// Report the SHAPE, not the text: a connection string can carry a
			// host or an account name, and this message can reach a log.
			throw ProtocolError("the connection string is not a sequence of key=value pairs");
		}
		const std::string key = LowerAscii(connection.substr(i, key_end - i));
		size_t value_start = key_end + 1;

		std::string value;
		if (value_start < connection.size() && (connection[value_start] == '\'' || connection[value_start] == '"')) {
			// Quoted: the only way to end a value in something that looks like a
			// key, or to keep a trailing semicolon.
			const char quote = connection[value_start];
			size_t j = value_start + 1;
			while (j < connection.size() && connection[j] != quote) {
				j++;
			}
			if (j >= connection.size()) {
				throw ProtocolError("the connection string has an unterminated quoted value");
			}
			value = connection.substr(value_start + 1, j - value_start - 1);
			i = j + 1;
		} else {
			// Unquoted: run to the next `key=` token or a semicolon. That is what
			// lets `catalog=Adventure Works port=2383` yield both, rather than
			// swallowing the port into the catalog name.
			size_t j = value_start;
			size_t ignored = 0;
			while (j < connection.size() && connection[j] != ';' && !KeyTokenAt(connection, j, ignored)) {
				j++;
			}
			value = Trim(connection.substr(value_start, j - value_start));
			i = j;
		}

		if (options.count(key)) {
			throw ProtocolError("the connection string sets '" + key + "' more than once");
		}
		options[key] = value;
	}
	return options;
}

}  // namespace xmla
