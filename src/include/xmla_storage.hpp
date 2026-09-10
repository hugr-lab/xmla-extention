//! The ATTACH entry point.
#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

void RegisterXmlaStorage(ExtensionLoader &loader);

}  // namespace duckdb
