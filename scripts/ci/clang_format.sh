#!/usr/bin/env bash
# Format (or check) with the SAME clang-format CI pins, through a container.
#
#   scripts/ci/clang_format.sh --check    dry run, non-zero if anything differs
#   scripts/ci/clang_format.sh --fix      rewrite in place
#
# CI pins clang-format-14 and newer versions disagree with it: a local
# clang-format 23 reformatted two files in a way 14 rejected, discoverable only
# by pushing. Running the pinned version locally is the only way the answer does
# not depend on what happens to be installed.
#
# This is a script rather than Makefile recipes because the quoting required to
# pass `find ... \( -name '*.cpp' \)` through make variable expansion into
# `bash -c` inside `docker run` is not worth maintaining — the first attempt
# produced a shell syntax error before it ran anything.
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE="${1:---check}"
IMAGE=ubuntu:24.04

case "$MODE" in
    --check|--fix) ;;
    *) echo "usage: $0 [--check|--fix]" >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 || {
    echo "clang-format: docker is required (CI pins clang-format-14; a local version will disagree)" >&2
    exit 1
}

# The container runs as root because apt-get needs it, and `clang-format -i`
# writes through the bind mount. On Linux that leaves every touched file owned
# by root in the working tree; macOS hides it behind Docker Desktop's UID
# mapping, so only a Linux contributor would ever meet it. Hand the ids in and
# restore ownership afterwards.
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# -i is load-bearing: without it `docker run` does not attach stdin, `bash -s`
# reads EOF immediately, runs NOTHING, and exits 0. Both --check and --fix then
# report success having done nothing at all — which is exactly the vacuous-pass
# failure mode the rest of this repository's checks are built to refuse. Caught
# only by testing that --check FAILS on a deliberately misformatted file.
docker run --rm -i -v "$PWD":/src -w /src \
    -e MODE="$MODE" -e HOST_UID="$HOST_UID" -e HOST_GID="$HOST_GID" \
    "$IMAGE" bash -s <<'INNER'
set -euo pipefail

# `</dev/null` on both apt calls is load-bearing, and this cost a while to see.
# The script arrives on the container's STDIN (`bash -s`), and apt-get reads
# stdin — so it SWALLOWED the rest of this script. The shell then hit EOF and
# exited 0, meaning --check reported success having never run clang-format at
# all, and --fix reformatted nothing. Both looked like they worked.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null </dev/null
apt-get install -y -qq clang-format-14 >/dev/null </dev/null

# An empty file list is a broken invocation, not a pass — the same guard ci.yml
# carries. Without it a renamed directory makes `find` fail while `xargs -0 -r`
# does nothing and exits 0, so the check succeeds having checked nothing.
count=$(find src test tools \( -name '*.cpp' -o -name '*.hpp' \) -print | grep -c '' || true)
if [ "$count" -eq 0 ]; then
    echo "clang-format: found 0 sources -- the file list is broken, which is not a pass" >&2
    exit 1
fi
echo "clang-format-14 over $count file(s)"

status=0
if [ "$MODE" = "--fix" ]; then
    find src test tools \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
        | xargs -0 -r clang-format-14 -i
    chown -R "$HOST_UID:$HOST_GID" src test tools
else
    find src test tools \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
        | xargs -0 -r clang-format-14 --dry-run --Werror || status=$?
fi
exit "$status"
INNER
