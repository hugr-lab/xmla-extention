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

# Run the gate in the sandbox and capture BOTH verdict and stderr.
#
# Reducing a case to its exit code cannot tell "scanned and found clean" from
# "never scanned" — which is failure mode 1 in the header, and would leave six of
# these cases reporting ok if materialise started failing for every file. A BLOCK
# expectation has the mirror problem: it cannot tell a connection-string finding
# from an unrelated refusal. So PASS cases assert the file was actually counted,
# and BLOCK cases assert WHY.
gate_stderr=""
gate_verdict=""
# Sets the two globals. Deliberately NOT `verdict=$(run_gate)`: a command
# substitution is a subshell, so the stderr capture would never reach the caller
# — which is precisely the bug this suite exists to pin in the gate itself, and
# the first version of this helper had it too.
run_gate() {
    local err_file="$SANDBOX/.gate_stderr"
    if (cd "$SANDBOX" && "$GATE") >/dev/null 2>"$err_file"; then
        gate_verdict=PASS
    else
        gate_verdict=BLOCK
    fi
    gate_stderr=$(cat "$err_file" 2>/dev/null || true)
    rm -f "$err_file"
}

# run_case <name> <expected PASS|BLOCK> <staged content> [worktree content] [expected reason]
run_case() {
    local name="$1" want="$2" staged="$3" worktree="${4:-}" reason="${5:-}"
    printf '%s' "$staged" > "$SANDBOX/f.md"
    git -C "$SANDBOX" add f.md
    if [ -n "$worktree" ]; then
        printf '%s' "$worktree" > "$SANDBOX/f.md"
    fi
    run_gate
    local got="$gate_verdict"
    git -C "$SANDBOX" rm -q --cached f.md >/dev/null 2>&1
    rm -f "$SANDBOX/f.md"
    report "$name" "$got" "$want"
    if [ "$got" = "BLOCK" ] && [ -n "$reason" ]; then
        # Counted as its own case, so the denominator does not move with the
        # numerator: previously a reason failure made the total read 18 instead
        # of 17.
        case "$gate_stderr" in
            *"$reason"*) echo "  ok    ^ refused for: $reason"; pass=$((pass + 1)) ;;
            *) echo "  FAIL  ^ blocked, but not for '$reason'"; fail=$((fail + 1)) ;;
        esac
    fi
}

CONN_REASON="host/SID/connection-string token"

echo "staged-content semantics:"
run_case "a secret staged, working tree cleaned, still blocks"  BLOCK "$SECRET"  "$CLEAN"  "$CONN_REASON"
run_case "clean staged, working tree dirty, still passes"       PASS  "$CLEAN"   "$SECRET"
run_case "a secret staged and on disk blocks"                   BLOCK "$SECRET"  ""        "$CONN_REASON"
run_case "clean staged and on disk passes"                      PASS  "$CLEAN"   ""

# A file staged with content and then deleted from disk is still going into the
# commit. `-f` on the working-tree path would skip it entirely.
printf '%s' "$SECRET" > "$SANDBOX/gone.md"
git -C "$SANDBOX" add gone.md
rm -f "$SANDBOX/gone.md"
run_gate
report "a secret staged, then removed from disk, still blocks" "$gate_verdict" "BLOCK"
git -C "$SANDBOX" rm -q --cached gone.md >/dev/null 2>&1

# A staged RENAME. `--diff-filter=ACM` excludes R, and rename detection is on by
# default, so `git mv` plus an edit produced an R entry that appeared in no file
# list and was scanned in neither direction. Verified failing open before the fix.
git -C "$SANDBOX" commit -q --allow-empty -m base
for i in $(seq 1 40); do echo "filler line $i"; done > "$SANDBOX/orig.md"
git -C "$SANDBOX" add orig.md
git -C "$SANDBOX" commit -q -m "add orig"
git -C "$SANDBOX" mv orig.md renamed.md
printf '%s' "$SECRET" >> "$SANDBOX/renamed.md"
git -C "$SANDBOX" add -A
run_gate
report "a staged rename carrying a secret blocks" "$gate_verdict" "BLOCK"
git -C "$SANDBOX" reset -q --hard HEAD

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
run_gate
report "an unreviewed binary is refused, not silently passed" "$gate_verdict" "BLOCK"
case "$gate_stderr" in
    *"binary file cannot be scanned"*) echo "  ok    ^ refused for: binary file cannot be scanned"; pass=$((pass + 1)) ;;
    *) echo "  FAIL  ^ the binary refusal did not name the reason"; fail=$((fail + 1)) ;;
esac

# The digest must describe the STAGED bytes. Hashing the working tree attests to
# a blob other than the one being committed, so an allowlist entry could vouch
# for content that never lands. Staging one binary and leaving different bytes on
# disk is what tells the two apart — a test that leaves identical bytes passes
# against the old working-tree-hashing code too.
if command -v sha256sum >/dev/null 2>&1; then
    staged_digest=$(git -C "$SANDBOX" cat-file blob :b.bin | sha256sum | cut -d" " -f1)
else
    staged_digest=$(git -C "$SANDBOX" cat-file blob :b.bin | shasum -a 256 | cut -d" " -f1)
fi
printf '\x00\xff\xfeDIFFERENT\x00' > "$SANDBOX/b.bin"
run_gate
report "a binary is refused by its STAGED digest" "$gate_verdict" "BLOCK"
case "$gate_stderr" in
    *"$staged_digest"*) echo "  ok    ^ named the staged digest"; pass=$((pass + 1)) ;;
    *) echo "  FAIL  ^ named a digest other than the staged one"; fail=$((fail + 1)) ;;
esac
git -C "$SANDBOX" rm -q --cached -f b.bin >/dev/null 2>&1; rm -f "$SANDBOX/b.bin"

# A cleanup that silently fails poisons every later case with a stale staged
# file, and the failure presents as an unrelated case failing. Assert it instead
# of trusting it.
assert_index_clean() {
    local left
    left=$(git -C "$SANDBOX" diff --cached --name-only -z --diff-filter=ACMRT | tr '\0' ' ')
    if [ -n "$left" ]; then
        echo "  FAIL  index not clean after '$1': [$left]"
        fail=$((fail + 1))
        git -C "$SANDBOX" reset -q >/dev/null 2>&1
    fi
}
assert_index_clean "binaries"

echo "quoted paths:"
# With core.quotePath at its default, git renders this filename as a quoted,
# octal-escaped string. The gate asked cat-file for a path including the literal
# quotes, that failed, and `|| continue` swallowed it — the file was silently not
# scanned. Fail-open on any repository with a non-ASCII filename.
printf '%s' "$SECRET" > "$SANDBOX/café.md"
git -C "$SANDBOX" add "café.md"
run_gate
report "a secret in a non-ASCII filename still blocks" "$gate_verdict" "BLOCK"
# The REASON matters here. Without -z the gate receives "caf\303\251.md" with
# literal quotes, cat-file fails, and the file is refused as unreadable — which
# blocks, but blocks without having scanned anything. Asserting the
# connection-string reason is what proves the content was actually read.
case "$gate_stderr" in
    *"host/SID/connection-string token"*)
        echo "  ok    ^ the file was scanned, not merely refused as unreadable"; pass=$((pass + 1)) ;;
    *)  echo "  FAIL  ^ blocked without scanning the content: $gate_stderr"; fail=$((fail + 1)) ;;
esac
git -C "$SANDBOX" rm -q --cached "café.md" >/dev/null 2>&1
rm -f "$SANDBOX/café.md"

assert_index_clean "quoted paths"

echo "submodules:"
# A gitlink is a commit id, not a blob, so there is no content in THIS repository
# to scan and skipping it is correct. It must be an EXPLICIT skip keyed on the
# index MODE: `git cat-file -t ":path"` does not report "commit" for a gitlink,
# it fails outright, so a blanket failure handler would either refuse every
# submodule or hide every real read error.
#
# The entry is created with update-index rather than `submodule add`, which needs
# a second repository and protocol.file.allow and can fail for reasons that have
# nothing to do with the gate.
# A sha that is NOT an object in this repository, which is what a real submodule
# gitlink looks like: it names a commit in the SUBMODULE's history. Pointing it
# at a blob that happens to exist here makes cat-file succeed and the case pass
# whether or not the gate skips gitlinks at all — the first version of this
# fixture did exactly that and could not fail.
absent_sha=0123456789abcdef0123456789abcdef01234567
# Checked: if update-index ever fails (a git version that validates the object,
# a verify_path rejection) the index stays empty, the gate exits 0 on an empty
# list, and the case reports ok having tested nothing.
if git -C "$SANDBOX" update-index --add --cacheinfo "160000,$absent_sha,vendored" 2>/dev/null; then
    run_gate
    report "a submodule gitlink is skipped, not refused as unreadable" "$gate_verdict" "PASS"
else
    # No fall-through. Reporting the FAIL and then running the case anyway
    # produced an "ok" line for a gate that scanned an empty index — the
    # misleading pass this suite exists to eliminate.
    echo "  FAIL  could not create the gitlink fixture; the submodule case tested nothing"
    fail=$((fail + 1))
fi
git -C "$SANDBOX" update-index --force-remove vendored 2>/dev/null

assert_index_clean "submodules"

echo "hygiene:"
# The scan directory was created inside a command substitution, so the parent
# never learned of it and the cleanup trap removed nothing: every staged file
# leaked a directory containing its staged blob into $TMPDIR. The gate writing
# out the secrets it exists to catch, and never deleting them.
# A PRIVATE TMPDIR. Counting entries in the shared /tmp makes the result depend
# on every other process on the machine: a concurrent mktemp fails the test and
# blames the gate, and a concurrent cleanup masks a real leak.
priv=$(mktemp -d)
before=$(find "$priv" -maxdepth 1 -name 'tmp.*' 2>/dev/null | grep -c '' || true)
for n in 1 2 3; do printf 'clean %s\n' "$n" > "$SANDBOX/h$n.md"; git -C "$SANDBOX" add "h$n.md"; done
if (cd "$SANDBOX" && TMPDIR="$priv" "$GATE") >/dev/null 2>&1; then gate_verdict=PASS; else gate_verdict=BLOCK; fi
after=$(find "$priv" -maxdepth 1 -name 'tmp.*' 2>/dev/null | grep -c '' || true)
rm -rf "$priv"
git -C "$SANDBOX" rm -q --cached h1.md h2.md h3.md >/dev/null 2>&1
rm -f "$SANDBOX"/h*.md
# The verdict is asserted too. `before` is 0 by construction (a fresh mktemp -d),
# so `after -le before` reduces to `after == 0` — which is ALSO what a gate that
# aborted before creating scan_dir produces. Without this the case printed "ok"
# for a gate that did nothing, the very failure mode this suite rejects.
if [ "$gate_verdict" != "PASS" ]; then
    echo "  FAIL  the hygiene run did not pass, so 'no leaked directory' proves nothing"
    fail=$((fail + 1))
elif [ "$after" -le "$before" ]; then
    echo "  ok    the scan directory is cleaned up"
    pass=$((pass + 1))
else
    echo "  FAIL  leaked $((after - before)) scan director(ies) for 3 staged files"
    fail=$((fail + 1))
fi

echo "invocation modes:"
if (cd "$REPO_ROOT" && LEAK_GATE_FILES_CMD="git ls-files -z" "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "an explicit file list scans the whole tree" "$got" "PASS"

# The list command MUST emit NUL-delimited paths now. A caller that forgets is a
# broken invocation, and the gate must refuse rather than mis-parse — this case
# is what caught the ci.yml invocation when -z was introduced.
if (cd "$REPO_ROOT" && LEAK_GATE_FILES_CMD="git ls-files" "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "a newline-delimited file list is refused, not mis-parsed" "$got" "BLOCK"
if (cd "$REPO_ROOT" && LEAK_GATE_FILES_CMD="true" "$GATE") >/dev/null 2>&1; then got=PASS; else got=BLOCK; fi
report "an explicit list that yields nothing is refused" "$got" "BLOCK"

echo
echo "$((pass + fail)) case(s), $fail failed"
[ "$fail" -eq 0 ]
