#include "xmla_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

//! Registers nothing yet, on purpose.
//!
//! T-001 is the skeleton: it exists so that LOAD works, the version is
//! reportable, and the DuckDB build, the community-extension metadata and the
//! CI matrix can all be exercised before any surface depends on them. The
//! table functions and the ATTACH path land in T-034..T-037, above the protocol
//! layer that already speaks to a live instance.
static void LoadInternal(ExtensionLoader &loader) {
	(void)loader;
}

void XmlaExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string XmlaExtension::Name() {
	return "xmla";
}

std::string XmlaExtension::Version() const {
#ifdef XMLA_VERSION
	return XMLA_VERSION;
#else
	return DefaultVersion();
#endif
}

}  // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(xmla, loader) {
	duckdb::LoadInternal(loader);
}
}
