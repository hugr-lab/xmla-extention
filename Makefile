PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXT_NAME=xmla
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Provides: release, debug, test, clean, set_duckdb_version, and the platform
# matrix targets the community-extension CI drives.
include extension-ci-tools/makefiles/duckdb_extension.Makefile

.PHONY: test-protocol check format format-check probe

# Run the spike against a live instance, in a Linux container. Needs XMLA_HOST;
# see "Running the probe against a live instance" in README.md.
probe:
	./scripts/run-probe.sh

# CI pins clang-format-14, and newer versions disagree with it — a local
# clang-format 23 reformatted two files in a way 14 rejected, which is only
# discoverable by pushing. These targets run the SAME version CI does, through a
# container, so the answer does not depend on what a contributor happens to have
# installed.
CLANG_FORMAT_IMAGE=ubuntu:24.04
CLANG_FORMAT_SETUP=apt-get update -qq >/dev/null && apt-get install -y -qq clang-format-14 >/dev/null
CLANG_FORMAT_FIND=find src test tools \( -name '*.cpp' -o -name '*.hpp' \) -print0

format:
	docker run --rm -v "$(PROJ_DIR)":/src -w /src $(CLANG_FORMAT_IMAGE) bash -c \
		"$(CLANG_FORMAT_SETUP); $(CLANG_FORMAT_FIND) | xargs -0 -r clang-format-14 -i"

format-check:
	docker run --rm -v "$(PROJ_DIR)":/src -w /src $(CLANG_FORMAT_IMAGE) bash -c \
		"$(CLANG_FORMAT_SETUP); $(CLANG_FORMAT_FIND) | xargs -0 -r clang-format-14 --dry-run --Werror"

# The hermetic protocol suite: no DuckDB, no server, no security library.
# constitution III requires this to pass on a machine that has never contacted
# an Analysis Services instance, and it also passes on one that has never had
# Kerberos installed.
test-protocol:
	cmake -S . -B build/protocol -DCMAKE_BUILD_TYPE=Debug -DXMLA_REQUIRE_GSS=OFF
	cmake --build build/protocol --target xmla_test
	./build/protocol/xmla_test

# Everything CI enforces, runnable in one command before pushing.
check: test-protocol format-check
	./scripts/ci/check_layering.sh
	./scripts/ci/check_locale_independence.sh
	./test/hooks/test_leak_gate.sh
	LEAK_GATE_FILES_CMD="git ls-files -z" .githooks/pre-commit
