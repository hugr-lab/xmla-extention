#!/usr/bin/env bash
# Regression tests for .githooks/pre-commit.
#
# The gate is the enforcement of constitution I, so it needs tests more than most
# code here does — and it has now failed in three distinct ways that all LOOKED
# like it was working:
#
#   1. It scanned the WORKING TREE while taking its file list from the index.
#      Stage a secret, edit it out without re-staging, and the gate scanned the
#      cleaned copy and passed the staged secret. Fails OPEN.
#   2. Its EXIT trap ended on a failing test, which sets the script's exit
#      status, so every run returned 1. A gate that blocks everything is
#      indistinguishable from a gate that works, right up until someone reaches
#      for --no-verify.
#   3. A four-component window inside an OID read as an IPv4 address.
#
# Cases A and B are the pair that matters: the gate is only correct if it blocks
# a staged secret AND passes staged-clean content. Testing only the first would
# have passed while it was broken in both directions.
#
# Everything runs in a THROWAWAY REPOSITORY. Staging fixtures into the real index
# makes the results depend on whatever else the developer happens to have staged
# — the first version of this file reported seven failures for exactly that
# reason, none of them about the gate.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GATE="$REPO_ROOT/.githooks/pre-commit"

SANDBOX=$(mktemp -d)
trap 'rm -rf "$SANDBOX"' EXIT

git -C "$SANDBOX" init -q
git -C "$SANDBOX" config user.email t@example.invalid
git -C "$SANDBOX" config user.name  t

pass=0
fail=0

# Fixtures are ASSEMBLED, never written as literals. The gate scans this file
# too, and it cannot tell a synthetic sample from a real one — which is the
# correct design: a gate that could tell would be one that could be talked out
# of a finding. This file blocked its own commit twice before that sank in.
SECRET="note
$(printf 'Data Source')=example-host;$(printf 'User ID')=svc
"
CLEAN='note
all clean
'
BAD_IP="host at $(printf '10.20')$(printf '.30.40')
"
SID="id $(printf 'S-1')-5-21-1-2-3-1001
"
NETBIOS="box $(printf 'WIN')-A1B2C3D4
"
OID='the OID is 1.3.6.1.4.1.311.2.2.10
'
LOOPBACK='loopback 127.0.0.1
'
DOCS_IP='docs use 192.0.2.5
'

report() {
    if [ "$2" = "$3" ]; then
        echo "  ok    $1"
        pass=$((pass + 1))
    else
        echo "  FAIL  $1: got $2, wanted $3"
        fail=$((fail + 1))
    fi
}

# run_case <name> <expected PASS|BLOCK> <staged content> [working-tree content]
run_case() {
    local name="$1" want="$2" staged="$3" worktree="${4:-}"
    printf '%s' "$staged" > "$SANDBOX/f.md"
    git -C "$SANDBOX" add f.md
    if [ -n "$worktree" ]; then
        printf '%s' "$worktree" > "$SANDBOX/f.md"
    fi
    local got
    if (cd "$SANDBOX" && "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
    git -C "$SANDBOX" rm -q --cached f.md >/dev/null 2>&1
    rm -f "$SANDBOX/f.md"
    report "$name" "$got" "$want"
}

echo "staged-content semantics:"
run_case "a secret staged, working tree cleaned, still blocks"  BLOCK "$SECRET"  "$CLEAN"
run_case "clean staged, working tree dirty, still passes"       PASS  "$CLEAN"   "$SECRET"
run_case "a secret staged and on disk blocks"                   BLOCK "$SECRET"  ""
run_case "clean staged and on disk passes"                      PASS  "$CLEAN"   ""

echo "token classes:"
run_case "a non-reserved IPv4 blocks"                           BLOCK "$BAD_IP"  ""
run_case "a security identifier blocks"                         BLOCK "$SID"     ""
run_case "a NetBIOS machine name blocks"                        BLOCK "$NETBIOS" ""
run_case "an OID is not an address"                             PASS  "$OID"     ""
run_case "a loopback address is allowed"                        PASS  "$LOOPBACK" ""
run_case "a documentation address is allowed"                   PASS  "$DOCS_IP"  ""

echo "binaries:"
# grep -I skips binaries, so every content check silently passes on one. The gate
# must refuse what it cannot read rather than report clean on a file it never
# scanned — that is how a coverage database carrying home-directory paths once
# reached a public repository.
printf '\x00\x01\x02binary\x00' > "$SANDBOX/b.bin"
git -C "$SANDBOX" add b.bin
if (cd "$SANDBOX" && "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "an unreviewed binary is refused, not silently passed" "$got" "BLOCK"
git -C "$SANDBOX" rm -q --cached b.bin >/dev/null 2>&1; rm -f "$SANDBOX/b.bin"

echo "invocation modes:"
if (cd "$REPO_ROOT" && LEAK_GATE_FILES_CMD="git ls-files" "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "an explicit file list scans the whole tree" "$got" "PASS"
if (cd "$REPO_ROOT" && LEAK_GATE_FILES_CMD="true" "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "an explicit list that yields nothing is refused" "$got" "BLOCK"

echo
echo "$((pass + fail)) case(s), $fail failed"
[ "$fail" -eq 0 ]
