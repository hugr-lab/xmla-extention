//===----------------------------------------------------------------------===//
// The table functions: xmla_discover and xmla_execute.
//
// These are the surface that does not need ATTACH, and together they already
// exceed what the Windows-only `msolap` extension offers — that provides one
// function, msolap(connection_string, dax_query), with no way to ask for
// metadata at all.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

void RegisterXmlaFunctions(ExtensionLoader &loader);

}  // namespace duckdb
