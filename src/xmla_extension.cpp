#include "xmla_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "xmla_functions.hpp"
#include "xmla_secret.hpp"
#include "xmla_storage.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	// A credential must not travel in a connection string: that string reaches
	// the query log, the plan, and any error echoing the statement.
	RegisterXmlaSecretType(loader);
	// xmla_discover and xmla_execute. Together these already exceed the
	// Windows-only msolap extension, which offers one function and no way to
	// ask for metadata at all.
	RegisterXmlaFunctions(loader);
	// ATTACH ... (TYPE xmla): the instance's catalogs become schemas and their
	// tables become tables, which is what makes SHOW ALL TABLES and DESCRIBE
	// work without this extension implementing either.
	RegisterXmlaStorage(loader);
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
