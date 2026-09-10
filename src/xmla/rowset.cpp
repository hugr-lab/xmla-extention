#include "xmla/rowset.hpp"

#include "xmla/errors.hpp"

#include <cctype>
#include <cstddef>
#include <stdexcept>

namespace xmla {

namespace {

//! XML whitespace is exactly these four characters (XML 1.0 §2.3), so this is
//! not merely locale-independence -- it is the correct definition. isspace()
//! follows LC_CTYPE and in some locales accepts more, which would let a byte XML
//! does not treat as whitespace end a tag name here.
bool XmlSpace(char c) {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

//! Decode the XML name encoding SSAS uses for rowset column names.
//!
//! A character that cannot appear in an XML element name is escaped as
//! `_xHHHH_`, the four-hex-digit code point. `EVALUATE ROW("answer", 42)`
//! therefore comes back as a column literally named `_x005B_answer_x005D_`,
//! which is `[answer]` — unusable as a SQL column name and unrecognisable to
//! whoever wrote the query.
//!
//! Only an exact `_xHHHH_` is decoded. Anything else is left alone, so a column
//! genuinely named `my_x_axis` survives.
std::string DecodeXmlName(const std::string &name) {
	if (name.find("_x") == std::string::npos) {
		return name;  // the overwhelmingly common case
	}
	std::string out;
	out.reserve(name.size());
	size_t i = 0;
	while (i < name.size()) {
		// _xHHHH_ is exactly 7 characters.
		if (name[i] == '_' && i + 6 < name.size() && (name[i + 1] == 'x' || name[i + 1] == 'X') && name[i + 6] == '_') {
			unsigned long cp = 0;
			bool hex = true;
			for (size_t k = i + 2; k < i + 6; k++) {
				const char c = name[k];
				unsigned digit;
				if (c >= '0' && c <= '9') {
					digit = static_cast<unsigned>(c - '0');
				} else if (c >= 'a' && c <= 'f') {
					digit = static_cast<unsigned>(c - 'a' + 10);
				} else if (c >= 'A' && c <= 'F') {
					digit = static_cast<unsigned>(c - 'A' + 10);
				} else {
					hex = false;
					break;
				}
				cp = cp * 16 + digit;
			}
			// Surrogates are not scalar values; leaving the escape intact is
			// better than emitting CESU-8, for the same reason as in
			// DecodeEntities.
			if (hex && cp != 0 && !(cp >= 0xD800 && cp <= 0xDFFF)) {
				if (cp < 0x80) {
					out.push_back(static_cast<char>(cp));
				} else if (cp < 0x800) {
					out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
					out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
				} else {
					out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
					out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
					out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
				}
				i += 7;
				continue;
			}
		}
		out.push_back(name[i++]);
	}
	return out;
}

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

//! Find the next tag at or after `from`. Returns false when the buffer holds no
//! complete tag from there on.
//!
//! Comments, CDATA, processing instructions and doctypes are SKIPPED rather than
//! parsed, because each of them can contain '<' and '>' and a scanner that does
//! not know that will read their contents as markup.
//!
//! `resume`, when given, receives how far the skipping got. The streaming parser
//! persists it so a construct already skipped is not skipped again on the next
//! call: without it, a document arriving in n pieces rescans every earlier
//! comment n times, which is quadratic in a peer-supplied length.
bool NextTag(const std::string &s, size_t from, Tag &tag, size_t *resume = nullptr) {
	const auto give_up = [&](size_t reached) {
		if (resume) {
			*resume = reached;
		}
		return false;
	};
	while (true) {
		const size_t lt = s.find('<', from);
		if (lt == std::string::npos) {
			// Nothing markup-ish is pending, so a resuming caller may skip the
			// whole buffer.
			return give_up(s.size());
		}
		if (s.compare(lt, 4, "<!--") == 0) {
			const size_t close = s.find("-->", lt + 4);
			if (close == std::string::npos) {
				// Resume AT the '<': the construct is retried whole once its
				// terminator arrives.
				return give_up(lt);
			}
			from = close + 3;
			continue;
		}
		if (s.compare(lt, 9, "<![CDATA[") == 0) {
			const size_t close = s.find("]]>", lt + 9);
			if (close == std::string::npos) {
				// Resume AT the '<': the construct is retried whole once its
				// terminator arrives.
				return give_up(lt);
			}
			from = close + 3;
			continue;
		}
		if (s.compare(lt, 2, "<?") == 0) {
			const size_t close = s.find("?>", lt + 2);
			if (close == std::string::npos) {
				// Resume AT the '<': the construct is retried whole once its
				// terminator arrives.
				return give_up(lt);
			}
			from = close + 2;
			continue;
		}
		if (s.compare(lt, 2, "<!") == 0) {
			const size_t close = s.find('>', lt + 2);
			if (close == std::string::npos) {
				// Resume AT the '<': the construct is retried whole once its
				// terminator arrives.
				return give_up(lt);
			}
			from = close + 1;
			continue;
		}

		const size_t gt = s.find('>', lt + 1);
		if (gt == std::string::npos) {
			return give_up(lt);
		}
		tag.begin = lt;
		tag.end = gt + 1;
		size_t p = lt + 1;
		tag.is_close = (p < s.size() && s[p] == '/');
		if (tag.is_close) {
			p++;
		}
		const size_t name_start = p;
		while (p < gt && !XmlSpace(s[p]) && s[p] != '/' && s[p] != '>') {
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

size_t Rowset::ColumnIndex(const std::string &name) const {
	for (size_t i = 0; i < columns.size(); i++) {
		if (columns[i] == name) {
			return i;
		}
	}
	return NO_COLUMN;
}

const std::string *Rowset::RowView::FindIndex(size_t column) const {
	for (const Cell *cell = begin_; cell != end_; ++cell) {
		if (cell->column == column) {
			return &cell->value;
		}
	}
	return nullptr;
}

const std::string *Rowset::RowView::Find(const std::string &name) const {
	if (!columns_) {
		return nullptr;
	}
	for (size_t i = 0; i < columns_->size(); i++) {
		if ((*columns_)[i] == name) {
			return FindIndex(i);
		}
	}
	return nullptr;
}

const std::string &Rowset::RowView::At(const std::string &name) const {
	const std::string *found = Find(name);
	if (!found) {
		// Same contract as std::map::at, which this replaced. A caller reaching
		// for a column that is absent from THIS row has confused "null" with
		// "empty", and the two mean different things in XMLA.
		throw std::out_of_range("xmla: no column '" + name + "' in this row");
	}
	return *found;
}

Rowset::RowView Rowset::Row(size_t i) const {
	if (i + 1 >= row_starts.size()) {
		// These indices come from a peer's byte stream by way of a caller's
		// arithmetic. An empty view is a wrong answer; reading off the end is a
		// crash.
		return RowView(nullptr, nullptr, &columns);
	}
	const Cell *base = cells.data();
	return RowView(base + row_starts[i], base + row_starts[i + 1], &columns);
}

void Rowset::AppendRow(std::vector<Cell> &&row) {
	if (cells.size() + row.size() > UINT32_MAX) {
		// row_starts is uint32 to halve its footprint. MessageStream caps an
		// unparsed message at 64 MiB, and a cell costs more than one byte, so
		// this is unreachable through the transport - which is exactly why it is
		// checked rather than assumed.
		throw ProtocolError("rowset exceeds the addressable number of cells");
	}
	for (auto &cell : row) {
		cells.push_back(std::move(cell));
	}
	row_starts.push_back(static_cast<uint32_t>(cells.size()));
	row.clear();
}

void RowStreamParser::Append(const char *data, size_t size) {
	buffer_.append(data, size);
}

uint32_t RowStreamParser::ColumnFor(const std::string &name) {
	for (size_t i = 0; i < columns_.size(); i++) {
		if (columns_[i] == name) {
			return static_cast<uint32_t>(i);
		}
	}
	if (columns_.size() >= UINT32_MAX) {
		throw ProtocolError("rowset declares more columns than can be indexed");
	}
	columns_.push_back(name);
	return static_cast<uint32_t>(columns_.size() - 1);
}

void RowStreamParser::SetCell(uint32_t column, std::string value) {
	// LAST WINS on a repeated element within one row, which is what the
	// std::map assignment this replaced did. Silently keeping the first would be
	// a different answer for the same bytes.
	for (auto &cell : row_) {
		if (cell.column == column) {
			cell.value = std::move(value);
			return;
		}
	}
	Cell cell;
	cell.column = column;
	cell.value = std::move(value);
	row_.push_back(std::move(cell));
}

void RowStreamParser::Compact() {
	// Only BETWEEN rows. Inside one, pending_from_ is an absolute offset into
	// the buffer and dropping a prefix would silently shift the text a value is
	// read from.
	if (pos_ == 0 || row_depth_ >= 0 || !pending_field_.empty()) {
		return;
	}
	buffer_.erase(0, pos_);
	pos_ = 0;
}

bool RowStreamParser::Next(std::vector<Cell> &out) {
	Compact();
	Tag tag;
	for (;;) {
		size_t resume = pos_;
		if (!NextTag(buffer_, pos_, tag, &resume)) {
			// No COMPLETE tag from here. Whether that is "wait" or "that was
			// everything" is the caller's to decide - it knows whether the peer
			// is done - and either way there is no row to hand back now.
			pos_ = resume;
			return false;
		}
		pos_ = tag.end;
		const std::string local = LocalName(tag.qname);

		if (tag.is_close) {
			// Clamped. Unmatched leading close tags drove this negative, after
			// which row_depth went negative too, every `row_depth >= 0` guard
			// failed, and the function returned an EMPTY rowset with no error —
			// indistinguishable from "no catalogs visible to this account",
			// which this layer documents as a meaningful answer.
			if (depth_ > 0) {
				depth_--;
			}
			// depth has already been decremented, so a direct child of <row>
			// closes at row_depth + 1: <row> itself sits AT row_depth.
			if (!pending_field_.empty() && row_depth_ >= 0 && depth_ == row_depth_ + 1) {
				// Closing a direct child of <row>: its text is the value.
				SetCell(ColumnFor(pending_field_), TextUntilMarkup(buffer_, pending_from_));
				pending_field_.clear();
			}
			if (row_depth_ >= 0 && depth_ == row_depth_ && local == "row") {
				out.clear();
				out.swap(row_);
				row_depth_ = -1;
				return true;
			}
			continue;
		}

		if (tag.self_closing) {
			// A self-closing child of <row> is an empty value, which is distinct
			// from an absent column.
			if (row_depth_ >= 0 && depth_ == row_depth_ + 1) {
				SetCell(ColumnFor(DecodeXmlName(local)), std::string());
			}
			continue;
		}

		if (local == "row" && row_depth_ < 0) {
			row_depth_ = depth_;
			row_.clear();
			depth_++;
			continue;
		}
		if (row_depth_ >= 0 && depth_ == row_depth_ + 1) {
			pending_field_ = DecodeXmlName(local);
			pending_from_ = tag.end;
		}
		depth_++;
	}
}

Rowset ParseRowset(const std::string &text) {
	// One scanner, two entry points. Everything this function used to do inline
	// now lives in RowStreamParser, so the streaming path and the whole-document
	// path cannot disagree about what a row is.
	RowStreamParser parser;
	parser.Append(text);
	parser.Finish();

	Rowset out;
	std::vector<Cell> row;
	while (parser.Next(row)) {
		out.AppendRow(std::move(row));
	}
	// AFTER the rows: a column that is null in every row until the last is not
	// in the union until that row has been seen.
	out.columns = parser.columns();
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
			const bool left_ok = (at == 0) || XmlSpace(attrs[at - 1]);
			size_t after = at + attribute.size();
			while (after < attrs.size() && XmlSpace(attrs[after])) {
				after++;
			}
			if (!left_ok || after >= attrs.size() || attrs[after] != '=') {
				at += attribute.size();
				continue;
			}
			after++;
			while (after < attrs.size() && XmlSpace(attrs[after])) {
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
