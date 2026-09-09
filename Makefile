PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXT_NAME=xmla
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Provides: release, debug, test, clean, set_duckdb_version, and the platform
# matrix targets the community-extension CI drives.
include extension-ci-tools/makefiles/duckdb_extension.Makefile

.PHONY: test-protocol check

# The hermetic protocol suite: no DuckDB, no server, no security library.
# constitution III requires this to pass on a machine that has never contacted
# an Analysis Services instance, and it also passes on one that has never had
# Kerberos installed.
test-protocol:
	cmake -S . -B build/protocol -DCMAKE_BUILD_TYPE=Debug -DXMLA_REQUIRE_GSS=OFF
	cmake --build build/protocol --target xmla_test
	./build/protocol/xmla_test

# Everything CI enforces, runnable in one command before pushing.
check: test-protocol
	./scripts/ci/check_layering.sh
	./scripts/ci/check_locale_independence.sh
	./test/hooks/test_leak_gate.sh
	LEAK_GATE_FILES_CMD="git ls-files -z" .githooks/pre-commit
