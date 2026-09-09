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
            *) return 1 ;;
        esac
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
    if ! "$RUNTIME" system status >/dev/null 2>&1 \
       || "$RUNTIME" system status 2>&1 | grep -qi "not running"; then
        echo "starting the container system service"
        "$RUNTIME" system start
    fi
fi

echo "building $IMAGE"
if [ "$APPLE" = "1" ]; then
    "$RUNTIME" build --tag "$IMAGE" --file docker/probe/Dockerfile .
else
    "$RUNTIME" build --platform linux/amd64 -t "$IMAGE" -f docker/probe/Dockerfile .
fi

# A previous run left behind is a confusing failure; remove it quietly.
"$RUNTIME" rm "$NAME" >/dev/null 2>&1 || true

# Environment is passed with -e so no value reaches the process list of another
# user, and none of it is echoed here.
set -- \
    -e "XMLA_TEST_HOST=$XMLA_HOST" \
    -e "XMLA_TEST_PORT=$XMLA_PORT" \
    -e "XMLA_TEST_MECHANISM=$XMLA_MECHANISM"
[ -n "${XMLA_USER:-}" ]     && set -- "$@" -e "XMLA_TEST_USER=$XMLA_USER"
[ -n "${XMLA_PASSWORD:-}" ] && set -- "$@" -e "XMLA_TEST_PASSWORD=$XMLA_PASSWORD"
[ -n "${XMLA_CATALOG:-}" ]  && set -- "$@" -e "XMLA_TEST_CATALOG=$XMLA_CATALOG"
[ -n "${XMLA_SPN:-}" ]      && set -- "$@" -e "XMLA_TEST_SPN=$XMLA_SPN"

echo "running the probe (mechanism: $XMLA_MECHANISM)"
if [ "$APPLE" = "1" ]; then
    exec "$RUNTIME" run --rm --name "$NAME" "$@" "$IMAGE"
else
    exec "$RUNTIME" run --rm --platform linux/amd64 --name "$NAME" "$@" "$IMAGE"
fi
