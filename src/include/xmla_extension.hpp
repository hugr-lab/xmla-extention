//===----------------------------------------------------------------------===//
// The DuckDB-facing half of the extension.
//
// Everything under src/xmla/ is DELIBERATELY free of DuckDB headers, so the
// protocol can be tested on a machine that has never contacted an Analysis
// Services instance and has no Kerberos library installed (constitution III).
// This file is where that boundary is crossed, and scripts/ci/check_layering.sh
// makes crossing it anywhere else a build failure.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"

namespace duckdb {

class XmlaExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};

}  // namespace duckdb
