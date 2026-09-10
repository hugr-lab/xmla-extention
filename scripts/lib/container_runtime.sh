# Pick a Linux container runtime, and start its daemon if it needs starting.
#
# Sourced, not executed. Sets:
#
#   XMLA_RUNTIME            path to the runtime binary
#   XMLA_RUNTIME_IS_APPLE   1 for Apple's `container`, 0 for Docker
#
# and defines xmla_container_build / xmla_container_run, which paper over the one
# difference that matters between the two: Apple's `container` takes no
# --platform flag.
#
# This lives in its own file because both scripts that need it need the SAME
# subtleties, and each one below was a real failure that cost real time. A second
# copy would drift from the first silently.

# ---------------------------------------------------------------------------
# For Apple's `container`, WHICH BINARY matters more than which version. The
# network plugin needs com.apple.security.virtualization, a restricted
# entitlement macOS grants only to a signature chaining to a certificate Apple
# authorised for it. A Homebrew bottle is rebuilt and ad-hoc signed: it declares
# the entitlement and is not granted it, and the symptom is a container that
# starts, gets a DHCP lease, and passes no traffic.
#
# Both installs can coexist, and Homebrew's is usually first on PATH, so the
# signed one is selected explicitly rather than by name.
# ---------------------------------------------------------------------------
xmla_plugin_is_signed() {
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
        # caller silently fell back to the ad-hoc Homebrew one, which is the
        # exact install this check exists to avoid.
        local info
        info=$(codesign -dvvv "$plugin" 2>&1 || true)
        case "$info" in
            *"TeamIdentifier=UPBK2H6LZM"*) return 0 ;;
        esac
        # Keep looking. Returning here decided the answer from the FIRST layout
        # that happens to exist, and this is written for the case where BOTH
        # layouts are present — so an ad-hoc plugin sitting in the path checked
        # first would condemn an install whose signed plugin is in the other.
    done
    return 1
}

xmla_select_runtime() {
    local candidate
    XMLA_RUNTIME=""
    for candidate in /usr/local/bin/container "$(command -v container 2>/dev/null || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        if xmla_plugin_is_signed "$candidate"; then
            XMLA_RUNTIME="$candidate"
            break
        fi
    done

    if [ -z "$XMLA_RUNTIME" ] && command -v container >/dev/null 2>&1; then
        cat >&2 <<'WARN'
warning: the only `container` found is ad-hoc signed (a Homebrew bottle).
  Its network plugin declares com.apple.security.virtualization but macOS will
  not grant it, so containers start and pass no traffic. Install Apple's signed
  package from the GitHub release and re-run:
      sudo installer -pkg container-<ver>-installer-signed.pkg -target /
  Continuing anyway; if the container cannot reach the network, this is why.
WARN
        XMLA_RUNTIME=$(command -v container)
    fi

    XMLA_RUNTIME_IS_APPLE=1
    if [ -z "$XMLA_RUNTIME" ]; then
        command -v docker >/dev/null 2>&1 || {
            printf 'no usable `container` or `docker` runtime found.\n' >&2
            return 1
        }
        XMLA_RUNTIME=$(command -v docker)
        XMLA_RUNTIME_IS_APPLE=0
    fi
    printf 'runtime: %s (%s)\n' "$XMLA_RUNTIME" "$("$XMLA_RUNTIME" --version 2>&1 | head -1)"

    # -----------------------------------------------------------------------
    # The daemon is not started after a reboot, and every subcommand then fails
    # with an opaque XPC error that reads like a broken install.
    # -----------------------------------------------------------------------
    if [ "$XMLA_RUNTIME_IS_APPLE" = "1" ]; then
        # Capture, then match — the same trap as codesign above, and it was
        # reintroduced here once. `... | grep -qi "not running"` has grep exit at
        # the first match while `container` is still writing, `container` takes
        # SIGPIPE, and `set -o pipefail` reports the pipeline as failed. The `||`
        # then reads that as "the daemon is fine" and skips the start.
        local status
        status=$("$XMLA_RUNTIME" system status 2>&1 || true)
        case "$status" in
            *"not running"*|*"not registered"*|*"Connection invalid"*|*"XPC"*)
                echo "starting the container system service"
                "$XMLA_RUNTIME" system start
                ;;
        esac
    fi
}

# xmla_container_build <image> <dockerfile> [context]
#
# XMLA_PLATFORM, when set, is passed to Docker only: Apple's `container` has no
# such flag and builds for the host.
xmla_container_build() {
    local image="$1" dockerfile="$2" context="${3:-.}"
    echo "building $image"
    if [ "$XMLA_RUNTIME_IS_APPLE" = "1" ]; then
        "$XMLA_RUNTIME" build --tag "$image" --file "$dockerfile" "$context"
    elif [ -n "${XMLA_PLATFORM:-}" ]; then
        "$XMLA_RUNTIME" build --platform "$XMLA_PLATFORM" -t "$image" -f "$dockerfile" "$context"
    else
        "$XMLA_RUNTIME" build -t "$image" -f "$dockerfile" "$context"
    fi
}

# xmla_container_run <args...> — everything after the flags is the image and its
# command, exactly as the runtime expects.
xmla_container_run() {
    if [ "$XMLA_RUNTIME_IS_APPLE" = "1" ] || [ -z "${XMLA_PLATFORM:-}" ]; then
        "$XMLA_RUNTIME" run "$@"
    else
        "$XMLA_RUNTIME" run --platform "$XMLA_PLATFORM" "$@"
    fi
}
