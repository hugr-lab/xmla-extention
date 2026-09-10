//===----------------------------------------------------------------------===//
// Parsing `host=... port=...` into fields.
//
// This lives in the PROTOCOL layer, with no DuckDB dependency, for one reason:
// so it can be tested by the hermetic suite. The first version sat above the
// seam and threw BinderException, which made it untestable without a database —
// and it shipped with a bug the tests would have caught immediately: it split
// only on ';' while the documented form is space-separated, so
// `host=x port=2383` parsed as a single pair and the port silently stayed 0.
//===----------------------------------------------------------------------===//
#pragma once

#include <map>
#include <string>

namespace xmla {

//! Key/value options from a connection string, keys lower-cased.
//!
//! Values may contain spaces: a value runs until the next `key=` token or a
//! semicolon, so `catalog=Adventure Works port=2383` yields both. A value may
//! also be single- or double-quoted, which is the only way to end a value in
//! something that looks like a key.
//!
//! Throws ProtocolError on a malformed string. It does NOT decide which keys
//! are meaningful — that belongs to the caller, which knows its own option set.
std::map<std::string, std::string> ParseConnectionString(const std::string &connection);

}  // namespace xmla
