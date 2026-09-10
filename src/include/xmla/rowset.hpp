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

#include <cstdint>
#include <string>
#include <vector>

namespace xmla {

//! One column's value in one row.
struct Cell {
	//! Index into the owning Rowset's or parser's column list.
	uint32_t column = 0;
	std::string value;
};

struct Rowset {
	//! Column names in first-seen order. XMLA omits null columns from a row, so
	//! the union across rows is the schema and no single row need carry it.
	std::vector<std::string> columns;

	//! Every present value, in row-major order, each tagged with its column.
	//!
	//! This replaced a std::map<std::string, std::string> per row. A row is
	//! SPARSE - XMLA omits a null column entirely - so a dense rows x columns
	//! array would need a validity mask beside it, and the map paid for a
	//! red-black node and a duplicated column NAME for every value in every row.
	//! Tagged cells carry absence for free and cost one uint32 per value. On the
	//! DBSCHEMA_COLUMNS response of a modest model - 1366 rows of ~30 columns -
	//! that is 40k string keys not allocated.
	std::vector<Cell> cells;

	//! Row i occupies cells[row_starts[i] .. row_starts[i + 1]).
	//!
	//! Always carries a leading 0, so it is never empty and size() needs no
	//! special case.
	std::vector<uint32_t> row_starts = {0};

	//! Returned by ColumnIndex for a name that is not in `columns`.
	static const size_t NO_COLUMN = static_cast<size_t>(-1);

	size_t size() const {
		return row_starts.size() - 1;
	}
	bool empty() const {
		return size() == 0;
	}

	//! Index of a column by name, or NO_COLUMN.
	//!
	//! Linear. A rowset has tens of columns, not thousands, and the scan path
	//! resolves an index ONCE per query rather than once per row - which is the
	//! whole reason the per-row map went away.
	size_t ColumnIndex(const std::string &name) const;

	//! A borrowed view of one row's cells. Cheap to copy; does not own anything.
	class RowView {
	public:
		RowView(const Cell *begin, const Cell *end, const std::vector<std::string> *columns)
			: begin_(begin), end_(end), columns_(columns) {}

		const Cell *begin() const {
			return begin_;
		}
		const Cell *end() const {
			return end_;
		}
		size_t size() const {
			return static_cast<size_t>(end_ - begin_);
		}

		//! nullptr when the column is not present IN THIS ROW, which is distinct
		//! from present-and-empty: XMLA sends `<D/>` for the empty string and
		//! omits the element entirely for null.
		const std::string *Find(const std::string &name) const;
		//! The same, by column index - for a caller that resolved the index once.
		const std::string *FindIndex(size_t column) const;
		//! Throws std::out_of_range when absent, like std::map::at.
		const std::string &At(const std::string &name) const;
		bool Has(const std::string &name) const {
			return Find(name) != nullptr;
		}

	private:
		const Cell *begin_;
		const Cell *end_;
		const std::vector<std::string> *columns_;
	};

	//! Row `i`. Out of range yields an empty view rather than undefined
	//! behaviour: these indices are derived from a peer's byte stream.
	RowView Row(size_t i) const;

	//! Append one row's cells. The cells' column indices must already refer to
	//! `columns`.
	void AppendRow(std::vector<Cell> &&row);
};

struct Fault {
	bool present = false;
	std::string code;
	std::string message;
};

//! A resumable, row-at-a-time scanner over a rowset document.
//!
//! Bytes go in through Append as they arrive; whole rows come out through Next.
//! Nothing waits for the end of the document, which is what lets a scan stop
//! reading a fact table after the rows it was asked for (T-042).
//!
//! ParseRowset is implemented ON THIS rather than beside it. Two scanners over
//! the same grammar would drift, and this one is a fuzz target: keeping a single
//! implementation means every existing rowset test also covers the streaming
//! path, and a divergence is a test failure rather than a difference only the
//! streaming caller sees.
class RowStreamParser {
public:
	void Append(const char *data, size_t size);
	void Append(const std::string &chunk) {
		Append(chunk.data(), chunk.size());
	}

	//! No more bytes will arrive. Next() then drains what is buffered.
	void Finish() {
		finished_ = true;
	}

	//! Pull the next complete row into `out`.
	//!
	//! False means "not yet" before Finish() and "no more" after it. The caller
	//! distinguishes them; this class does not guess.
	bool Next(std::vector<Cell> &out);

	//! The column union discovered SO FAR. It grows as rows arrive, because a
	//! column that is null in every row up to here has not been seen yet.
	const std::vector<std::string> &columns() const {
		return columns_;
	}

	//! Bytes held but not yet consumed. A caller that feeds from a socket uses
	//! this to bound what an unterminated document can accumulate.
	size_t buffered() const {
		return buffer_.size() - pos_;
	}

private:
	uint32_t ColumnFor(const std::string &name);
	void SetCell(uint32_t column, std::string value);
	void Compact();

	std::string buffer_;
	size_t pos_ = 0;
	bool finished_ = false;

	// Scanner state, carried across Append/Next calls.
	int depth_ = 0;
	int row_depth_ = -1;
	std::string pending_field_;
	size_t pending_from_ = 0;

	std::vector<std::string> columns_;
	std::vector<Cell> row_;
};

//! Parse a complete XMLA rowset response. Matches on LOCAL element names, so the
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
