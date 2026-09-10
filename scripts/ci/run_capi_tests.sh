#!/usr/bin/env bash
# The checks that need DuckDB's C API rather than sqllogictest.
#
# There is exactly one so far, and it exists because `access_mode` is a
# startup-only setting: `SET access_mode = 'read_write'` is refused once the
# database is running, so no .test file can put a session into the configuration
# that broke ATTACH. See test/capi/attach_access_mode.cpp.
#
# Compiled here rather than as a CMake target: the extension is built inside
# DuckDB's own tree, and adding a target there that links libduckdb is more
# machinery than one test file justifies.
#
#   BUILD_DIR   build/release   a tree produced by `make release`
set -euo pipefail

cd "$(dirname "$0")/../.."

BUILD_DIR="${BUILD_DIR:-build/release}"
EXTENSION="$BUILD_DIR/extension/xmla/xmla.duckdb_extension"

die() { printf 'capi: %s\n' "$*" >&2; exit 1; }

[ -f "$EXTENSION" ] || die "no extension at $EXTENSION. Run: make release"

# The shared library lands in <build>/src on every platform DuckDB builds for.
LIBDIR="$BUILD_DIR/src"
[ -d "$LIBDIR" ] || die "no library directory at $LIBDIR"

CXX="${CXX:-c++}"
OUT="$BUILD_DIR/capi_attach_access_mode"

"$CXX" -std=c++17 -o "$OUT" test/capi/attach_access_mode.cpp \
    -I duckdb/src/include -L "$LIBDIR" -lduckdb -Wl,-rpath,"$PWD/$LIBDIR"

# The absolute path matters: LOAD resolves a relative one against the database's
# directory, not the working directory.
"$OUT" "$PWD/$EXTENSION"
echo "capi: all checks passed"
