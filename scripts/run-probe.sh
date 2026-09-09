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

# ---------------------------------------------------------------------------
# Pick a runtime.
#
# For Apple's `container`, WHICH BINARY matters more than which version. The
# network plugin needs com.apple.security.virtualization, a restricted
# entitlement macOS grants only to a signature chaining to a certificate Apple
# authorised for it. A Homebrew bottle is rebuilt and ad-hoc signed: it declares
# the entitlement and is not granted it, and the symptom is a container that
# starts, gets a DHCP lease, and passes no traffic.
#
# Both installs coexist on this machine and Homebrew's is first on PATH, so the
# signed one is selected explicitly rather than by name.
# ---------------------------------------------------------------------------
plugin_is_signed() {
    local bin="$1" root plugin
    root=$(dirname "$(dirname "$bin")")
    for plugin in \
        "$root/libexec/container/plugins/container-network-vmnet/bin/container-network-vmnet" \
        "$root/libexec/container-plugins/container-network-vmnet/bin/container-network-vmnet"; do
        [ -e "$plugin" ] || continue
        # Capture, THEN match. `codesign ... | grep -q` looks obvious and is
        # wrong under `set -o pipefail`: grep -q exits on the first match,
        # codesign takes SIGPIPE, and pipefail reports the pipeline as FAILED
        # even though it matched — so the signed runtime was rejected and the
        # script silently fell back to the ad-hoc Homebrew one, which is the
        # exact install this check exists to avoid.
        local info
        info=$(codesign -dvvv "$plugin" 2>&1 || true)
        case "$info" in
            *"TeamIdentifier=UPBK2H6LZM"*) return 0 ;;
        esac
        # Keep looking. Returning here decided the answer from the FIRST layout
        # that happens to exist, and this script is written for the case where
        # BOTH layouts are present — so an ad-hoc plugin sitting in the path
        # checked first would condemn an install whose signed plugin is in the
        # other.
    done
    return 1
}

RUNTIME=""
for candidate in /usr/local/bin/container "$(command -v container 2>/dev/null || true)"; do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    if plugin_is_signed "$candidate"; then
        RUNTIME="$candidate"
        break
    fi
done

if [ -z "$RUNTIME" ] && command -v container >/dev/null 2>&1; then
    cat >&2 <<'WARN'
warning: the only `container` found is ad-hoc signed (a Homebrew bottle).
  Its network plugin declares com.apple.security.virtualization but macOS will
  not grant it, so containers start and pass no traffic. Install Apple's signed
  package from the GitHub release and re-run:
      sudo installer -pkg container-<ver>-installer-signed.pkg -target /
  Continuing anyway; if the probe cannot reach the instance, this is why.
WARN
    RUNTIME=$(command -v container)
fi

APPLE=1
if [ -z "$RUNTIME" ]; then
    command -v docker >/dev/null 2>&1 || die "no usable 'container' or 'docker' runtime found."
    RUNTIME=$(command -v docker)
    APPLE=0
fi
printf 'runtime: %s (%s)\n' "$RUNTIME" "$("$RUNTIME" --version 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# The daemon is not started after a reboot, and every subcommand then fails with
# an opaque XPC error that reads like a broken install.
# ---------------------------------------------------------------------------
if [ "$APPLE" = "1" ]; then
    # Capture, then match — the same trap this script fixes above for codesign,
    # and it was reintroduced here. `... | grep -qi "not running"` has grep exit
    # at the first match while `container` is still writing, `container` takes
    # SIGPIPE, and `set -o pipefail` reports the pipeline as failed. The `||`
    # then reads that as "the daemon is fine" and skips the start.
    daemon_status=$("$RUNTIME" system status 2>&1 || true)
    case "$daemon_status" in
        *"not running"*|*"not registered"*|*"Connection invalid"*|*"XPC"*)
            echo "starting the container system service"
            "$RUNTIME" system start
            ;;
    esac
fi

echo "building $IMAGE"
if [ "$APPLE" = "1" ]; then
    "$RUNTIME" build --tag "$IMAGE" --file docker/probe/Dockerfile .
else
    "$RUNTIME" build --platform linux/amd64 -t "$IMAGE" -f docker/probe/Dockerfile .
fi

# A previous run left behind is a confusing failure; remove it quietly.
"$RUNTIME" rm "$NAME" >/dev/null 2>&1 || true

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
if [ "$APPLE" = "1" ]; then
    "$RUNTIME" run --rm --name "$NAME" --env-file "$ENV_FILE" "$IMAGE"
else
    "$RUNTIME" run --rm --platform linux/amd64 --name "$NAME" --env-file "$ENV_FILE" "$IMAGE"
fi
