PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXT_NAME=xmla
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Provides: release, debug, test, clean, set_duckdb_version, and the platform
# matrix targets the community-extension CI drives.
# `-include`, not `include`: GNU make treats a missing include as FATAL before it
# selects a goal, so on a fresh clone without `git submodule update --init` even
# `make test-protocol` and `make check` died with "No such file or directory.
# Stop." — targets that need neither DuckDB nor the CI tools.
-include extension-ci-tools/makefiles/duckdb_extension.Makefile

# Say so plainly rather than letting `make release` fail with a missing-target
# error that points nowhere.
ifeq ($(wildcard extension-ci-tools/makefiles/duckdb_extension.Makefile),)
release debug:
	@echo "extension-ci-tools is missing. Run: git submodule update --init --recursive" >&2
	@exit 1
endif

.PHONY: test-protocol check fmt fmt-check probe

# NOT named `format`/`format-check`. extension-ci-tools/duckdb_extension.Makefile
# already declares both, and the include is processed first:
#
#   `format: format-check` upstream carries NO recipe, so GNU make MERGES the
#   prerequisite into ours instead of replacing it — silently, with no
#   "overriding recipe" warning. `make format` then ran the --Werror dry run
#   FIRST and aborted on the first misformatted file, which is precisely the
#   situation you run it to fix. The reformat never executed.
#
#   `format-check` upstream DOES carry a recipe, so make warned "overriding
#   commands for target format-check" on EVERY invocation in this repo, and
#   displaced the target that extension-ci-tools' own reusable code-quality
#   workflow calls.
#
# Both verified with `make -n`. Renaming sidesteps both, and leaves upstream's
# targets working if the community-extension workflow is ever wired up.
fmt:
	./scripts/ci/clang_format.sh --fix

fmt-check:
	./scripts/ci/clang_format.sh --check

# Run the spike against a live instance, in a Linux container. Needs XMLA_HOST;
# see "Running the probe against a live instance" in README.md.
probe:
	./scripts/run-probe.sh

# The hermetic protocol suite: no DuckDB, no server, no security library.
# constitution III requires this to pass on a machine that has never contacted
# an Analysis Services instance, and it also passes on one that has never had
# Kerberos installed.
test-protocol:
	cmake -S . -B build/protocol -DCMAKE_BUILD_TYPE=Debug -DXMLA_REQUIRE_GSS=OFF
	cmake --build build/protocol --target xmla_test
	./build/protocol/xmla_test

# Everything CI enforces, runnable in one command before pushing.
# Offline and dependency-free by design. fmt-check needs Docker and a network
# (it apt-installs clang-format on every run), so it is offered rather than
# required: `make check` must work on a plane.
check: test-protocol
	./scripts/ci/check_layering.sh
	./scripts/ci/check_locale_independence.sh
	@[ -f duckdb/src/include/duckdb.hpp ] \
		&& ./scripts/ci/check_extension_compiles.sh \
		|| echo "note: skipped extension compile (duckdb submodule not checked out)."
	./test/hooks/test_leak_gate.sh
	LEAK_GATE_FILES_CMD="git ls-files -z" .githooks/pre-commit
	@command -v docker >/dev/null 2>&1 \
		&& ./scripts/ci/clang_format.sh --check \
		|| echo "note: skipped clang-format (no docker). CI pins version 14; run 'make fmt-check' before pushing."
