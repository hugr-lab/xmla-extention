//===----------------------------------------------------------------------===//
// The DuckDB secret type that carries an Analysis Services credential.
//
// A password must not travel in a connection string: that string reaches the
// query log, the plan, and any error that echoes the ATTACH. XmlaConnectionParams
// refuses `password=` outright and points here.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

void RegisterXmlaSecretType(ExtensionLoader &loader);

}  // namespace duckdb
