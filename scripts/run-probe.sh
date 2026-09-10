#!/usr/bin/env bash
# Run the XMLA spike against a live Analysis Services instance, in a Linux
# container, using Apple's `container` runtime on macOS (Docker as a fallback).
#
# The probe must run on Linux: the NTLM path needs gss-ntlmssp, and macOS has no
# NTLM GSS mechanism at all — Apple's GSS.framework also exports no gss_wrap_iov
# (research D11). The container connects OUT to the instance, so nothing is
# published and no inbound path is involved.
#
#   XMLA_HOST      required   address of the instance. NOT stored anywhere: it
#                             changes whenever the fixture is restored, and a
#                             stale copy reads as a firewall or code fault
#                             rather than as stale config.
#   XMLA_PORT      2383       pinned. There is no named-instance redirector
#                             (research D9), so a wrong port presents as a hang.
#   XMLA_MECHANISM ntlm       ntlm | kerberos | negotiate
#   XMLA_USER      (unset)    principal; unset means the ambient identity
#   XMLA_PASSWORD  (unset)    standalone NTLM only; never echoed, never stored
#   XMLA_CATALOG   (unset)    exercises DBSCHEMA_TABLES/COLUMNS as well
#   XMLA_SPN       (unset)    full SPN override
#
# Nothing here is written to a file or printed: constitution I forbids a
# hostname, account name or realm in any committed file, and this script is
# committed.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=xmla-probe
NAME=xmla-probe

die() { printf '%s\n' "$*" >&2; exit 1; }

[ -n "${XMLA_HOST:-}" ] || die "XMLA_HOST is required. See 'Running the probe' in README.md."

XMLA_PORT="${XMLA_PORT:-2383}"
XMLA_MECHANISM="${XMLA_MECHANISM:-ntlm}"

# Runtime selection, the signed-binary check and the daemon start all live in
# scripts/lib/container_runtime.sh, because run-sql-tests.sh needs exactly the
# same subtleties and a second copy would drift from this one silently.
# shellcheck source=lib/container_runtime.sh
. "$(dirname "$0")/lib/container_runtime.sh"

# Docker on Apple silicon emulates this, which is slow but fine: the probe
# compiles four protocol files, not DuckDB. Pinned because every measurement
# recorded in research/ was taken on amd64.
export XMLA_PLATFORM="${XMLA_PLATFORM:-linux/amd64}"
xmla_select_runtime || die "no usable 'container' or 'docker' runtime found."

xmla_container_build "$IMAGE" docker/probe/Dockerfile .

# A previous run left behind is a confusing failure; remove it quietly.
"$XMLA_RUNTIME" rm "$NAME" >/dev/null 2>&1 || true

# --env-file, NOT -e.
#
# An earlier version passed these with `-e KEY=VALUE` and claimed that kept them
# out of another user's view. It does the opposite: -e puts the value in the
# `docker run` / `container run` ARGV, and /proc/<pid>/cmdline is world-readable
# on Linux — so the password and the instance address were visible to every
# local user for the life of the run. A 0600 file read by the runtime is not.
ENV_FILE=$(mktemp)
chmod 600 "$ENV_FILE"
cleanup() { rm -f "$ENV_FILE"; }
trap cleanup EXIT

{
    printf 'XMLA_TEST_HOST=%s\n' "$XMLA_HOST"
    printf 'XMLA_TEST_PORT=%s\n' "$XMLA_PORT"
    printf 'XMLA_TEST_MECHANISM=%s\n' "$XMLA_MECHANISM"
    [ -n "${XMLA_USER:-}" ]     && printf 'XMLA_TEST_USER=%s\n' "$XMLA_USER"
    [ -n "${XMLA_PASSWORD:-}" ] && printf 'XMLA_TEST_PASSWORD=%s\n' "$XMLA_PASSWORD"
    [ -n "${XMLA_CATALOG:-}" ]  && printf 'XMLA_TEST_CATALOG=%s\n' "$XMLA_CATALOG"
    [ -n "${XMLA_SPN:-}" ]      && printf 'XMLA_TEST_SPN=%s\n' "$XMLA_SPN"
    true
} > "$ENV_FILE"

echo "running the probe (mechanism: $XMLA_MECHANISM)"
# Not `exec`: the trap has to run so the credential file is removed.
xmla_container_run --rm --name "$NAME" --env-file "$ENV_FILE" "$IMAGE"
