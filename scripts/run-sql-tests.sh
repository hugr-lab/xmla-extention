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
#                             '"My Model"."FactInternetSales"'. Inserted into the
#                             SQL VERBATIM, unlike the other values, because it
#                             is an identifier and not a string literal.
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
# The container writes into the bind-mounted tree. On Linux with Docker it runs
# as root with no uid mapping, so everything the build produces under
# build/container — and anything it touches through the /src mount — comes out
# root-owned, and a later host-side `make clean` or `rm -rf build` needs sudo.
# scripts/ci/clang_format.sh already solves this the same way.
HOST_UID=$(id -u)
HOST_GID=$(id -g)
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

# Created on the host so the top directory belongs to the invoking user. What
# the container writes UNDER it is chown'd back at the end of the in-container
# script; see HOST_UID above.
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
    printf 'HOST_UID=%s\n' "$HOST_UID"
    printf 'HOST_GID=%s\n' "$HOST_GID"
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
set -uo pipefail
cd /src

# NOT `set -e` around the whole body. Everything below reports its own status
# and the chown at the end must run whatever happened — the same lesson as
# scripts/ci/clang_format.sh, where an early abort left the tree root-owned.
status=0

run_step() {
    local label="$1"
    shift
    echo
    echo "=== $label ==="
    if ! "$@"; then
        echo "FAILED: $label" >&2
        status=1
        return 1
    fi
    return 0
}

# A single-quoted SQL literal, with any quote doubled. Every value below comes
# from the environment and a password containing ' is legal and common: it used
# to terminate the literal early and produce a Parser Error that named a syntax
# problem rather than the input, after which every later statement failed
# against a secret that did not exist.
sql_literal() {
    local value="$1"
    printf "'%s'" "${value//\'/\'\'}"
}

# The cheap one first, so a protocol regression does not wait behind a DuckDB
# build. It configures its own tree with -DXMLA_REQUIRE_GSS=OFF and links no
# security library at all.
run_step "hermetic protocol suite (no sockets, no server, no GSSAPI)" make test-protocol

# The project's own target, not a bare `cmake -S . -B`. This repository's
# CMakeLists is the EXTENSION, and configuring it directly builds only the
# protocol library and the probe — no DuckDB, no extension, no unittest binary.
# `make release` configures DuckDB's tree with the extension wired in, which is
# what produces build/release/test/unittest. Getting this wrong looked like a
# missing file: "./build/container/test/unittest: No such file or directory".
export CMAKE_BUILD_PARALLEL_LEVEL="${XMLA_JOBS}"
if [ "$status" = 0 ]; then
    run_step "build the extension (incremental after the first run)" make release GEN=ninja
fi

if [ "$status" = 0 ]; then
    echo
    echo "=== SQL surface (server-free) ==="
    # Each file by name, and the run is CHECKED. `unittest` exits 0 when its
    # filter matches nothing — verified: a "test/sql/*.test" glob printed "No
    # tests ran" and exited 0 — so a typo here would make this whole step
    # vacuous AND green.
    sql_tests=$(ls test/sql/*.test 2>/dev/null || true)
    if [ -z "$sql_tests" ]; then
        echo "no test/sql/*.test found; nothing was checked" >&2
        status=1
    fi
    for t in $sql_tests; do
        echo "--- $t"
        out=$(./build/release/test/unittest --test-dir . "$t" 2>&1) || status=1
        printf '%s\n' "$out"
        case "$out" in
            *"All tests passed"*) ;;
            *) echo "no assertions ran for $t" >&2; status=1 ;;
        esac
    done
fi

# sqllogictest cannot set access_mode: it is startup-only. See
# test/capi/attach_access_mode.cpp.
if [ "$status" = 0 ]; then
    run_step "C API surface (server-free)" ./scripts/ci/run_capi_tests.sh
fi

if [ "$status" = 0 ] && [ -n "${XMLA_HOST:-}" ]; then
    echo
    echo "=== live instance ==="
    # Rendered here, inside the container, and never on the host. `duckdb -c`
    # would put the password in ARGV.
    SQL=$(mktemp)
    DDL=$(mktemp)
    chmod 600 "$SQL" "$DDL"

    {
        printf "CREATE SECRET s (TYPE xmla, HOST %s, PORT %s, MECHANISM %s" \
            "$(sql_literal "$XMLA_HOST")" "$XMLA_PORT" "$(sql_literal "$XMLA_MECHANISM")"
        [ -n "${XMLA_USER:-}" ]     && printf ", USER %s" "$(sql_literal "$XMLA_USER")"
        [ -n "${XMLA_PASSWORD:-}" ] && printf ", PASSWORD %s" "$(sql_literal "$XMLA_PASSWORD")"
        printf ");\n"
        if [ -n "${XMLA_CATALOG:-}" ]; then
            printf "ATTACH 'secret=s catalog=%s' AS live (TYPE xmla);\n" "$XMLA_CATALOG"
        else
            printf "ATTACH 'secret=s' AS live (TYPE xmla);\n"
        fi
    } > "$SQL"
    # The DDL refusal goes in its OWN script, because it is an EXPECTED failure
    # and the shell counts it: on piped stdin execution continues but
    # ProcessInput returns errCnt > 0, which becomes the exit status. With it in
    # the main script a completely successful live run reported failure — and,
    # worse, so did a broken one, so the section carried no signal at all.
    cp "$SQL" "$DDL"
    printf "CREATE SCHEMA live.nope;\n" >> "$DDL"

    {
        printf ".print --- the attachment is read-only ---\n"
        printf "SELECT 'ASSERT readonly=' || readonly AS check FROM duckdb_databases() WHERE database_name = 'live';\n"
        printf ".print --- tables visible ---\n"
        printf "SELECT 'ASSERT tables=' || count(*) AS check FROM (SHOW ALL TABLES) WHERE database = 'live';\n"
    } >> "$SQL"
    if [ -n "${XMLA_TABLE:-}" ]; then
        # VERBATIM: this is an identifier, not a string literal.
        {
            printf ".timer on\n"
            printf ".print --- DESCRIBE ---\n"
            printf "DESCRIBE live.%s;\n" "$XMLA_TABLE"
            printf ".print --- every column, LIMIT 5 (EVALUATE, abandoned early) ---\n"
            printf "SELECT * FROM live.%s LIMIT 5;\n" "$XMLA_TABLE"
            printf ".print --- count(*) (the EMPTY virtual column, one projected column) ---\n"
            printf "SELECT 'ASSERT rows=' || count(*) AS check FROM live.%s;\n" "$XMLA_TABLE"
            printf ".print --- ONE column over the whole table (the SELECTCOLUMNS projection) ---\n"
            # A multi-column projection is the case where output-position
            # mapping and column ordering matter, and count(*) does not reach
            # it: that narrows to one column by a different route. Dropping this
            # in the restructuring left the header promising a check that no
            # longer ran.
            printf "SELECT 'ASSERT narrow=' || count(c0) AS check FROM (SELECT * FROM live.%s) t(c0);\n" \
                "$XMLA_TABLE"
        } >> "$SQL"
    else
        printf ".print --- note: XMLA_TABLE is unset, so the scan checks were skipped ---\n" >> "$SQL"
    fi

    live_out=$(./build/release/duckdb -box < "$SQL" 2>&1) || status=1
    printf '%s\n' "$live_out"
    # Asserted, not merely displayed. Nothing here used to be checked, so a
    # failed ATTACH, a failed DESCRIBE and an all-NULL scan all looked the same.
    case "$live_out" in
        *"ASSERT readonly=true"*) ;;
        *) echo "the attachment did not report read-only" >&2; status=1 ;;
    esac
    case "$live_out" in
        *"ASSERT tables=0"*) echo "no tables were visible on the instance" >&2; status=1 ;;
        *"ASSERT tables="*) ;;
        *) echo "the table count did not come back" >&2; status=1 ;;
    esac
    if [ -n "${XMLA_TABLE:-}" ]; then
        # A FLOOR, like the table count above. `*"ASSERT rows="*` matched
        # `ASSERT rows=0` just as happily, so a regression that made every scan
        # return nothing — a broken cursor, a desynchronised unseal, a
        # projection naming a column the server does not have — left DESCRIBE,
        # SELECT and count(*) all exiting 0 and this section green. Zero is the
        # symptom this check exists to catch, not an answer.
        case "$live_out" in
            *"ASSERT rows=0"*) echo "the scan returned no rows" >&2; status=1 ;;
            *"ASSERT rows="*) ;;
            *) echo "the row count did not come back" >&2; status=1 ;;
        esac
        case "$live_out" in
            *"ASSERT narrow=0"*) echo "the narrow projection returned no rows" >&2; status=1 ;;
            *"ASSERT narrow="*) ;;
            *) echo "the narrow projection did not come back" >&2; status=1 ;;
        esac
    fi

    echo
    echo "=== DDL is refused (an EXPECTED failure, run on its own) ==="
    ddl_out=$(./build/release/duckdb -box < "$DDL" 2>&1)
    ddl_status=$?
    printf '%s\n' "$ddl_out"
    if [ "$ddl_status" = 0 ]; then
        echo "CREATE SCHEMA was NOT refused" >&2
        status=1
    fi
    case "$ddl_out" in
        *"read-only"*) ;;
        *) echo "the refusal did not name read-only" >&2; status=1 ;;
    esac
    rm -f "$SQL" "$DDL"
elif [ "$status" = 0 ]; then
    echo
    echo "note: XMLA_HOST is unset, so the live section was skipped."
fi

# ALWAYS, whatever happened above. See the note on `set -e` at the top.
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown -R "$HOST_UID:$HOST_GID" build 2>/dev/null || true
fi
exit "$status"
INNER
)

echo "running in $XMLA_RUNTIME (memory $MEMORY, $JOBS jobs, build cached in $BUILD_DIR)"
xmla_container_run --rm --name "$NAME" --env-file "$ENV_FILE" --memory "$MEMORY" \
    --volume "$PWD:/src" \
    --volume "$PWD/$BUILD_DIR:/src/build" \
    "$IMAGE" bash -c "$IN_CONTAINER"
