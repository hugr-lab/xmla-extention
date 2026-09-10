#!/usr/bin/env bash
# Syntax-check the DuckDB-facing sources against DuckDB's headers.
#
# These files compile ONLY inside the DuckDB build (the extension block in
# CMakeLists.txt is guarded on `if(COMMAND build_loadable_extension)`), and no CI
# job runs that build: the unit-test and sanitizer jobs build standalone, and so
# does CodeQL. So a syntax error, a wrong override signature, or a missing
# include in src/xmla_extension.cpp failed nothing anywhere — it would surface
# for the first time in a release build, or in a contributor's `make release`.
#
# A full DuckDB build takes ~10 minutes and needs a lot of memory. A syntax-only
# compile needs the submodule CHECKED OUT but not built, and takes seconds. It
# catches the class of error that can reach here.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ ! -f duckdb/src/include/duckdb.hpp ]; then
    echo "extension-compile: the duckdb submodule is not checked out" >&2
    echo "  run: git submodule update --init --recursive" >&2
    exit 1
fi

# Every source EXCEPT the protocol layer, at any depth.
#
# `-maxdepth 1` missed src/catalog/ entirely — five files that only compile
# inside the DuckDB build and were therefore checked by nothing at all, which is
# the exact gap this script exists to close. src/xmla/ is excluded because it is
# built (and tested) standalone by every other job.
files=$(find src -name '*.cpp' -not -path 'src/xmla/*' -print)
count=$(printf '%s\n' "$files" | grep -c '[^[:space:]]' || true)
if [ "$count" -eq 0 ]; then
    echo "extension-compile: found 0 sources -- the check is broken, which is not a pass" >&2
    exit 1
fi

CXX="${CXX:-c++}"
fail=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    # -DXMLA_VERSION is the load-bearing one. Without it this checked the OTHER
    # preprocessor branch: src/xmla_extension.cpp took its `#else`
    # (DefaultVersion()) path, so a defect in the branch that actually ships was
    # invisible to the very check meant to catch it.
    #
    # -DDUCKDB_BUILD_LOADABLE_EXTENSION is a NO-OP on the platforms this gate
    # runs on, and is passed only so the flags match the loadable target's. It
    # comes from DuckDB's own build_loadable_extension macro
    # (duckdb/extension/extension_build_tools.cmake), not from this repo's
    # CMakeLists, and it is consulted only under _WIN32
    # (duckdb/common/winapi.hpp) to pick between dllimport and dllexport. On
    # Linux and macOS it selects no branch, so it neither adds nor removes
    # coverage here.
    if ! "$CXX" -std=c++17 -fsyntax-only -DXMLA_VERSION='"0.0.0-syntax-check"' \
        -DDUCKDB_BUILD_LOADABLE_EXTENSION -Isrc/include -Iduckdb/src/include "$f"; then
        echo "extension-compile: $f does not compile against DuckDB's headers" >&2
        fail=1
    fi
done < <(printf '%s\n' "$files")

[ "$fail" = 0 ] || exit 1
echo "extension-compile: $count DuckDB-facing file(s) compile"
