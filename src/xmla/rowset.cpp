#include "xmla/rowset.hpp"

#include <cctype>
#include <cstddef>

namespace xmla {

namespace {

//! Local name of a possibly-prefixed tag: "urn:x:row" and "r:row" both give "row".
std::string LocalName(const std::string &qname) {
	const size_t colon = qname.rfind(':');
	return colon == std::string::npos ? qname : qname.substr(colon + 1);
}

//! Decode the five predefined entities plus numeric references.
//!
//! An unrecognised or malformed reference is passed through VERBATIM rather than
//! dropped. Dropping it silently changes a value the caller may be comparing
//! against a server-side one; passing it through is visibly wrong instead.
std::string DecodeEntities(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	size_t i = 0;
	while (i < in.size()) {
		if (in[i] != '&') {
			out.push_back(in[i++]);
			continue;
		}
		const size_t semi = in.find(';', i + 1);
		// Bound the search: an unterminated '&' in a large document must not scan
		// to the end of it for every occurrence.
		if (semi == std::string::npos || semi - i > 12) {
			out.push_back(in[i++]);
			continue;
		}
		const std::string ref = in.substr(i + 1, semi - i - 1);
		if (ref == "amp") {
			out.push_back('&');
		} else if (ref == "lt") {
			out.push_back('<');
		} else if (ref == "gt") {
			out.push_back('>');
		} else if (ref == "quot") {
			out.push_back('"');
		} else if (ref == "apos") {
			out.push_back('\'');
		} else if (ref.size() > 1 && ref[0] == '#') {
			unsigned long cp = 0;
			bool ok = false;
			try {
				cp = (ref[1] == 'x' || ref[1] == 'X') ? std::stoul(ref.substr(2), nullptr, 16)
													  : std::stoul(ref.substr(1), nullptr, 10);
				// Surrogates are not Unicode scalar values. Encoding one with the
				// 3-byte branch produces CESU-8, not UTF-8, and DuckDB's VARCHAR
				// requires well-formed UTF-8 — so it would surface as an
				// invalid-UTF-8 error attributed to the wrong layer.
				ok = cp != 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
			} catch (...) {
				ok = false;
			}
			if (!ok) {
				out.append(in, i, semi - i + 1);
				i = semi + 1;
				continue;
			}
			// Minimal UTF-8 encode.
			if (cp < 0x80) {
				out.push_back(static_cast<char>(cp));
			} else if (cp < 0x800) {
				out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
				out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
			} else if (cp < 0x10000) {
				out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
				out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
				out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
			} else {
				out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
				out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
				out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
				out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
			}
		} else {
			out.append(in, i, semi - i + 1);
			i = semi + 1;
			continue;
		}
		i = semi + 1;
	}
	return out;
}

struct Tag {
	std::string qname;
	bool is_close = false;
	bool self_closing = false;
	size_t begin = 0;  //!< index of '<'
	size_t end = 0;	   //!< index just past '>'
	size_t attrs_begin = 0;
	size_t attrs_end = 0;
};

//! Find the next tag at or after `from`. Returns false at end of input.
//!
//! Comments, CDATA, processing instructions and doctypes are SKIPPED rather than
//! parsed, because each of them can contain '<' and '>' and a scanner that does
//! not know that will read their contents as markup.
bool NextTag(const std::string &s, size_t from, Tag &tag) {
	while (true) {
		const size_t lt = s.find('<', from);
		if (lt == std::string::npos) {
			return false;
		}
		if (s.compare(lt, 4, "<!--") == 0) {
			const size_t close = s.find("-->", lt + 4);
			if (close == std::string::npos) {
				return false;
			}
			from = close + 3;
			continue;
		}
		if (s.compare(lt, 9, "<![CDATA[") == 0) {
			const size_t close = s.find("]]>", lt + 9);
			if (close == std::string::npos) {
				return false;
			}
			from = close + 3;
			continue;
		}
		if (s.compare(lt, 2, "<?") == 0) {
			const size_t close = s.find("?>", lt + 2);
			if (close == std::string::npos) {
				return false;
			}
			from = close + 2;
			continue;
		}
		if (s.compare(lt, 2, "<!") == 0) {
			const size_t close = s.find('>', lt + 2);
			if (close == std::string::npos) {
				return false;
			}
			from = close + 1;
			continue;
		}

		const size_t gt = s.find('>', lt + 1);
		if (gt == std::string::npos) {
			return false;
		}
		tag.begin = lt;
		tag.end = gt + 1;
		size_t p = lt + 1;
		tag.is_close = (p < s.size() && s[p] == '/');
		if (tag.is_close) {
			p++;
		}
		const size_t name_start = p;
		while (p < gt && !isspace(static_cast<unsigned char>(s[p])) && s[p] != '/' && s[p] != '>') {
			p++;
		}
		tag.qname = s.substr(name_start, p - name_start);
		tag.attrs_begin = p;
		tag.attrs_end = gt;
		tag.self_closing = (gt > lt + 1 && s[gt - 1] == '/');
		if (tag.qname.empty()) {
			from = gt + 1;
			continue;
		}
		return true;
	}
}

//! Text between `from` and the next '<', entity-decoded.
std::string TextUntilMarkup(const std::string &s, size_t from) {
	const size_t lt = s.find('<', from);
	const size_t end = (lt == std::string::npos) ? s.size() : lt;
	return DecodeEntities(s.substr(from, end - from));
}

}  // namespace

Rowset ParseRowset(const std::string &text) {
	Rowset out;
	size_t pos = 0;
	Tag tag;
	int row_depth = -1;
	int depth = 0;
	std::map<std::string, std::string> row;
	std::string pending_field;
	size_t pending_from = 0;

	while (NextTag(text, pos, tag)) {
		pos = tag.end;
		const std::string local = LocalName(tag.qname);

		if (tag.is_close) {
			// Clamped. Unmatched leading close tags drove this negative, after
			// which row_depth went negative too, every `row_depth >= 0` guard
			// failed, and the function returned an EMPTY rowset with no error —
			// indistinguishable from "no catalogs visible to this account",
			// which this layer documents as a meaningful answer.
			if (depth > 0) {
				depth--;
			}
			// depth has already been decremented, so a direct child of <row>
			// closes at row_depth + 1: <row> itself sits AT row_depth.
			if (!pending_field.empty() && row_depth >= 0 && depth == row_depth + 1) {
				// Closing a direct child of <row>: its text is the value.
				const std::string value = TextUntilMarkup(text, pending_from);
				if (row.find(pending_field) == row.end()) {
					bool known = false;
					for (const auto &c : out.columns) {
						if (c == pending_field) {
							known = true;
							break;
						}
					}
					if (!known) {
						out.columns.push_back(pending_field);
					}
				}
				row[pending_field] = value;
				pending_field.clear();
			}
			if (row_depth >= 0 && depth == row_depth && local == "row") {
				out.rows.push_back(row);
				row.clear();
				row_depth = -1;
			}
			continue;
		}

		if (tag.self_closing) {
			// A self-closing child of <row> is an empty value, which is distinct
			// from an absent column.
			if (row_depth >= 0 && depth == row_depth + 1) {
				bool known = false;
				for (const auto &c : out.columns) {
					if (c == local) {
						known = true;
						break;
					}
				}
				if (!known) {
					out.columns.push_back(local);
				}
				row[local] = std::string();
			}
			continue;
		}

		if (local == "row" && row_depth < 0) {
			row_depth = depth;
			row.clear();
			depth++;
			continue;
		}
		if (row_depth >= 0 && depth == row_depth + 1) {
			pending_field = local;
			pending_from = tag.end;
		}
		depth++;
	}
	return out;
}

Fault FindFault(const std::string &text) {
	Fault fault;
	// Cheap reject first: a fault is rare and this runs on every response.
	if (text.find("Fault") == std::string::npos && text.find("faultcode") == std::string::npos) {
		return fault;
	}
	std::string code;
	std::string message;
	const bool has_code = FindElementText(text, "faultcode", code);
	const bool has_message = FindElementText(text, "faultstring", message);
	if (!has_code && !has_message) {
		return fault;
	}
	fault.present = true;
	fault.code = code;
	fault.message = message;
	return fault;
}

bool FindElementText(const std::string &text, const std::string &local_name, std::string &out) {
	size_t pos = 0;
	Tag tag;
	while (NextTag(text, pos, tag)) {
		pos = tag.end;
		if (tag.is_close || tag.self_closing) {
			continue;
		}
		if (LocalName(tag.qname) != local_name) {
			continue;
		}
		out = TextUntilMarkup(text, tag.end);
		// Trim: fault text is routinely pretty-printed onto its own line.
		const size_t first = out.find_first_not_of(" \t\r\n");
		if (first == std::string::npos) {
			out.clear();
			return true;
		}
		const size_t last = out.find_last_not_of(" \t\r\n");
		out = out.substr(first, last - first + 1);
		return true;
	}
	return false;
}

bool FindAttribute(const std::string &text, const std::string &local_name, const std::string &attribute,
				   std::string &out) {
	size_t pos = 0;
	Tag tag;
	while (NextTag(text, pos, tag)) {
		pos = tag.end;
		if (tag.is_close) {
			continue;
		}
		if (LocalName(tag.qname) != local_name) {
			continue;
		}
		const std::string attrs = text.substr(tag.attrs_begin, tag.attrs_end - tag.attrs_begin);
		size_t at = 0;
		while ((at = attrs.find(attribute, at)) != std::string::npos) {
			// Must be a whole attribute name, not a suffix of a longer one.
			const bool left_ok = (at == 0) || isspace(static_cast<unsigned char>(attrs[at - 1]));
			size_t after = at + attribute.size();
			while (after < attrs.size() && isspace(static_cast<unsigned char>(attrs[after]))) {
				after++;
			}
			if (!left_ok || after >= attrs.size() || attrs[after] != '=') {
				at += attribute.size();
				continue;
			}
			after++;
			while (after < attrs.size() && isspace(static_cast<unsigned char>(attrs[after]))) {
				after++;
			}
			if (after >= attrs.size() || (attrs[after] != '"' && attrs[after] != '\'')) {
				return false;
			}
			const char quote = attrs[after];
			const size_t value_start = after + 1;
			const size_t value_end = attrs.find(quote, value_start);
			if (value_end == std::string::npos) {
				return false;
			}
			out = DecodeEntities(attrs.substr(value_start, value_end - value_start));
			return true;
		}
	}
	return false;
}

}  // namespace xmla
