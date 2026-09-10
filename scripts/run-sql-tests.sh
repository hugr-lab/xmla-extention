#!/usr/bin/env bash
# Build the extension and run the SQL surface on LINUX, from any host, in a
# container.
#
# `make test` on a Mac cannot exercise the parts that matter. The NTLM path needs
# gss-ntlmssp, which macOS does not have, and a macOS build links keg-only
# Homebrew krb5 and is not the artifact anyone ships. So the sqllogictest suite
# — and any check against a live instance — belongs in Linux, and this puts it
# there without asking anyone to keep a Linux box around.
#
# What it always does:
#
#   * builds a dependencies-only image (no source in it; see docker/test/)
#   * bind-mounts this repository at /src and a PERSISTENT build directory over
#     /src/build, so the second run is incremental rather than a 40-minute
#     rebuild of DuckDB — and so a host build of another platform is invisible
#     to the container
#   * runs the hermetic protocol suite, test/sql/*.test and the C API checks
#
# What it does only when XMLA_HOST is set:
#
#   * ATTACHes a live instance and reports how many tables it can see
#   * with XMLA_TABLE also set, runs the scan checks that nothing server-free can
#     reach: a full SELECT, a narrow SELECT (which exercises the SELECTCOLUMNS
#     projection pushdown), count(*) (which exercises the EMPTY virtual column),
#     and a LIMIT (which exercises abandoning the cursor early)
#
#   XMLA_HOST      (unset)    address of the instance. Enables the live section.
#                             NOT stored anywhere: it changes whenever the
#                             fixture is restored, and a stale copy reads as a
#                             firewall or code fault rather than as stale config.
#   XMLA_PORT      2383       pinned. There is no named-instance redirector
#                             (research D9), so a wrong port presents as a hang.
#   XMLA_MECHANISM ntlm       ntlm | kerberos | negotiate
#   XMLA_USER      (unset)    principal; unset means the ambient identity
#   XMLA_PASSWORD  (unset)    standalone NTLM only; never echoed, never stored
#   XMLA_CATALOG   (unset)    the model to attach; unset attaches every model
#   XMLA_TABLE     (unset)    schema-qualified table for the scan checks, e.g.
#                             '"My Model"."FactInternetSales"'
#   XMLA_PLATFORM  (host)     Docker only. Leave unset: a native build is very
#                             much faster than an emulated one, and nothing here
#                             depends on the architecture.
#   XMLA_MEMORY    8g         memory for the container. Apple's `container`
#                             defaults to about a gigabyte, which is not enough:
#                             the build died with "c++: fatal error: Killed
#                             signal terminated program cc1plus", which is the
#                             OOM killer and reads like a compiler bug.
#   XMLA_JOBS      4          build parallelism. Each DuckDB translation unit
#                             wants a lot of memory, so this multiplies against
#                             XMLA_MEMORY rather than against the core count —
#                             ninja's default of one job per core is what turned
#                             a big build into an OOM.
#
# Nothing is written to a committed file and nothing is echoed: constitution I
# forbids a hostname, account name or realm in any committed file, and this
# script is committed.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=xmla-test
NAME=xmla-test
MEMORY="${XMLA_MEMORY:-8g}"
JOBS="${XMLA_JOBS:-4}"
# The whole build/ tree, so `make release` (build/release) and `make
# test-protocol` (build/protocol) both land inside it. Mounted OVER /src/build,
# which also keeps a host build of a different platform out of the container's
# way.
BUILD_DIR=build/container

die() { printf '%s\n' "$*" >&2; exit 1; }

# shellcheck source=lib/container_runtime.sh
. "$(dirname "$0")/lib/container_runtime.sh"
xmla_select_runtime || die "no usable 'container' or 'docker' runtime found."

[ -f duckdb/src/include/duckdb.hpp ] ||
    die "the duckdb submodule is not checked out. Run: git submodule update --init --recursive"

xmla_container_build "$IMAGE" docker/test/Dockerfile .

# A container left behind by an interrupted run is a confusing failure — Apple's
# `container` reports "container with id xmla-test already exists" and stops,
# which reads like a name clash rather than the leftover it is. --rm does not
# cover a run that was killed.
"$XMLA_RUNTIME" rm --force "$NAME" >/dev/null 2>&1 || true

# Created on the host, not by the container, so it belongs to the invoking user
# and an incremental rebuild does not need root.
mkdir -p "$BUILD_DIR"

# --env-file, NOT -e.
#
# -e puts the value in the runtime's ARGV, and /proc/<pid>/cmdline is
# world-readable on Linux — so a password passed that way is visible to every
# local user for the life of the run. A 0600 file read by the runtime is not.
ENV_FILE=$(mktemp)
chmod 600 "$ENV_FILE"
cleanup() {
    rm -f "$ENV_FILE"
    return 0
}
trap cleanup EXIT

{
    printf 'XMLA_JOBS=%s\n' "$JOBS"
    printf 'XMLA_PORT=%s\n' "${XMLA_PORT:-2383}"
    printf 'XMLA_MECHANISM=%s\n' "${XMLA_MECHANISM:-ntlm}"
    [ -n "${XMLA_HOST:-}" ]     && printf 'XMLA_HOST=%s\n' "$XMLA_HOST"
    [ -n "${XMLA_USER:-}" ]     && printf 'XMLA_USER=%s\n' "$XMLA_USER"
    [ -n "${XMLA_PASSWORD:-}" ] && printf 'XMLA_PASSWORD=%s\n' "$XMLA_PASSWORD"
    [ -n "${XMLA_CATALOG:-}" ]  && printf 'XMLA_CATALOG=%s\n' "$XMLA_CATALOG"
    [ -n "${XMLA_TABLE:-}" ]    && printf 'XMLA_TABLE=%s\n' "$XMLA_TABLE"
    true
} > "$ENV_FILE"

# The in-container half. Kept as one heredoc rather than a committed file so
# that the SQL it renders — which interpolates a password — exists only inside
# the container, in /tmp, for the life of the run.
IN_CONTAINER=$(cat <<'INNER'
set -euo pipefail
cd /src

# The cheap one first, so a protocol regression does not wait behind a DuckDB
# build. It configures its own tree with -DXMLA_REQUIRE_GSS=OFF and links no
# security library at all.
echo "=== hermetic protocol suite (no sockets, no server, no GSSAPI) ==="
make test-protocol

echo
echo "=== build the extension (incremental after the first run) ==="
# Bounded on purpose. cmake --build honours this, and ninja's default of one job
# per core exhausted the container's memory: cc1plus was killed and gcc reported
# it as its own fatal error, which reads like a compiler bug rather than an OOM.
export CMAKE_BUILD_PARALLEL_LEVEL="${XMLA_JOBS}"
# The project's own target, not a bare `cmake -S . -B`. This repository's
# CMakeLists is the EXTENSION, and configuring it directly builds only the
# protocol library and the probe — no DuckDB, no extension, no unittest binary.
# `make release` configures DuckDB's tree with the extension wired in, which is
# what produces build/release/test/unittest. Getting this wrong looked like a
# missing file: "./build/container/test/unittest: No such file or directory".
make release GEN=ninja

echo
echo "=== SQL surface (server-free) ==="
# Each file by name, and the run is CHECKED. `unittest` exits 0 when its filter
# matches nothing — verified: a "test/sql/*.test" glob printed "No tests ran"
# and exited 0 — so a typo here would make this whole step vacuous AND green.
sql_tests=$(ls test/sql/*.test 2>/dev/null || true)
[ -n "$sql_tests" ] || { echo "no test/sql/*.test found; nothing was checked" >&2; exit 1; }
for t in $sql_tests; do
    echo "--- $t"
    out=$(./build/release/test/unittest --test-dir . "$t" 2>&1) || { printf '%s\n' "$out"; exit 1; }
    printf '%s\n' "$out"
    case "$out" in
        *"All tests passed"*) ;;
        *) echo "no assertions ran for $t" >&2; exit 1 ;;
    esac
done

echo
echo "=== C API surface (server-free) ==="
# sqllogictest cannot set access_mode: it is startup-only. See
# test/capi/attach_access_mode.cpp.
./scripts/ci/run_capi_tests.sh

[ -n "${XMLA_HOST:-}" ] || {
    echo
    echo "note: XMLA_HOST is unset, so the live section was skipped."
    exit 0
}

echo
echo "=== live instance ==="
# Rendered here, inside the container, and never on the host. `duckdb -c` would
# put the password in ARGV.
SQL=$(mktemp)
chmod 600 "$SQL"
trap 'rm -f "$SQL"' EXIT
{
    printf "CREATE SECRET s (TYPE xmla, HOST '%s', PORT %s, MECHANISM '%s'" \
        "$XMLA_HOST" "$XMLA_PORT" "$XMLA_MECHANISM"
    [ -n "${XMLA_USER:-}" ]     && printf ", USER '%s'" "$XMLA_USER"
    [ -n "${XMLA_PASSWORD:-}" ] && printf ", PASSWORD '%s'" "$XMLA_PASSWORD"
    printf ");\n"
    if [ -n "${XMLA_CATALOG:-}" ]; then
        printf "ATTACH 'secret=s catalog=%s' AS live (TYPE xmla);\n" "$XMLA_CATALOG"
    else
        printf "ATTACH 'secret=s' AS live (TYPE xmla);\n"
    fi
    printf ".print --- the attachment is read-only ---\n"
    printf "SELECT readonly FROM duckdb_databases() WHERE database_name = 'live';\n"
    printf ".print --- tables visible ---\n"
    printf "SELECT count(*) AS tables FROM (SHOW ALL TABLES) WHERE database = 'live';\n"
    if [ -n "${XMLA_TABLE:-}" ]; then
        printf ".timer on\n"
        printf ".print --- DESCRIBE ---\n"
        printf "DESCRIBE live.%s;\n" "$XMLA_TABLE"
        printf ".print --- every column, LIMIT 5 (EVALUATE, abandoned early) ---\n"
        printf "SELECT * FROM live.%s LIMIT 5;\n" "$XMLA_TABLE"
        printf ".print --- count(*) (the EMPTY virtual column, one projected column) ---\n"
        printf "SELECT count(*) AS n FROM live.%s;\n" "$XMLA_TABLE"
        printf ".print --- one column over the whole table (SELECTCOLUMNS projection) ---\n"
        printf "SELECT count(column00) AS n FROM (SELECT * FROM live.%s) t(column00);\n" "$XMLA_TABLE"
        printf ".print --- DDL is refused ---\n"
        printf "CREATE SCHEMA live.nope;\n"
    else
        printf ".print --- note: XMLA_TABLE is unset, so the scan checks were skipped ---\n"
    fi
} > "$SQL"
./build/release/duckdb -box < "$SQL"
INNER
)

echo "running in $XMLA_RUNTIME (memory $MEMORY, $JOBS jobs, build cached in $BUILD_DIR)"
xmla_container_run --rm --name "$NAME" --env-file "$ENV_FILE" --memory "$MEMORY" \
    --volume "$PWD:/src" \
    --volume "$PWD/$BUILD_DIR:/src/build" \
    "$IMAGE" bash -c "$IN_CONTAINER"
