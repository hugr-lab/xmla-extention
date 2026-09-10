//===----------------------------------------------------------------------===//
// Composing the DAX a table scan sends.
//
// Pure string work: names and a column list in, one statement out. It lives in
// the protocol library rather than beside the scan for the same reason
// ColumnMap does — it was unreachable from the hermetic suite while it sat in
// the extension's translation unit, and its failure mode is a column of nulls
// or a DAX error the caller never wrote.
//
// Every identifier is CHECKED rather than escaped. Escaping is the usual answer
// and it is the weaker one here: these names come from the server's own
// DBSCHEMA_COLUMNS, so a name carrying `]` or a quote is either a server this
// client should not trust or a case nobody has tested, and in both situations
// the right move is to stop composing and send the statement that was already
// known to work. Refusing costs a slower scan; a mis-escaped bracket costs a DAX
// expression nobody wrote.
//===----------------------------------------------------------------------===//
#pragma once

#include <string>
#include <vector>

namespace xmla {
namespace dax {

//! Whether a name may appear inside an identifier this code composes.
bool SafeName(const std::string &name);

//! `'Table'`. The caller has already checked the name.
std::string Table(const std::string &table);

//! `'Table'[Column]`.
std::string Column(const std::string &table, const std::string &column);

//! A DAX string literal. `"` is doubled rather than refused, because this is a
//! VALUE and not an identifier: a caller's own search term legitimately contains
//! quotes.
std::string StringLiteral(const std::string &value);

//! The statement for a table scan.
//!
//! `wanted` is the columns to project, in output order; `total_columns` is how
//! many the table has. A projection is composed only when it actually NARROWS
//! the transfer, every name involved is safe, and `columns_known` says the
//! column list came from the server rather than being a placeholder —
//! otherwise the result is plain `EVALUATE '<table>'`, which is the form that
//! has been exercised against a live instance since the first working scan.
//!
//! `columns_known` is a parameter rather than a caller-side condition because
//! it is a rule about the projection and belongs where the projection is
//! decided. As a caller-side condition it was safe only by accident: the
//! unknown case happens to be exactly one synthetic column, which can never
//! narrow, so a second placeholder would silently have started naming a column
//! the server does not have.
//!
//! SELECTCOLUMNS needs a tabular model at compatibility level 1200 or above
//! (SSAS 2016+). That floor is UNVERIFIED — no older instance is available to
//! this project — which is the other reason the narrowing condition is there.
//!
//! Throws ProtocolError when the TABLE name is unsafe. Not a fallback: the
//! plain form quotes the name too, so there is nothing safe to compose, and a
//! named refusal beats a DAX syntax error the operator cannot attribute.
std::string Evaluate(const std::string &table, const std::vector<std::string> &wanted, size_t total_columns,
					 bool columns_known);

}  // namespace dax
}  // namespace xmla
