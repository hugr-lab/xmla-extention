#!/usr/bin/env bash
# The protocol layer must not depend on the process locale.
#
# A DuckDB extension is loaded into a host process that may have called
# setlocale(LC_CTYPE, "") — CPython does, and so does R. Under tr_TR.UTF-8
# glibc's toupper('i') yields U+0130, which a cast to char truncates. Keyword,
# identifier and XML syntax on this path is ASCII by definition, so the locale
# has no business in it.
#
# Three defects this has already caught, none of which the tests could:
#   - a locale fix that silently did not apply, leaving the ASCII helpers with no
#     call sites (found by CodeQL as "unused static function", not by this)
#   - isspace in the XML scanner, where XML's own definition is narrower anyway
#   - a fault-message fold in client.cpp that decides an ERROR CATEGORY, and a
#     word-boundary test in redact.cpp that decides where a host or account name
#     ends — both on paths where a fold that stops matching leaks or misreports
#
# The file set is DISCOVERED, not listed. The first version hardcoded two files
# and went green while the same defect was live in two others.
set -euo pipefail

command -v perl >/dev/null 2>&1 || {
    # The comment stripper is not optional. Without it every file whose comment
    # EXPLAINS why these calls are avoided reports as a violation, and the
    # operator gets errors pointing at comment lines with no indication that the
    # stripper never ran. Falling back to `cat` did exactly that, silently.
    echo "locale: perl is required to strip comments before matching" >&2
    exit 1
}

files=$(find src/xmla src/include/xmla \( -name '*.cpp' -o -name '*.hpp' \) -print)

count=$(printf '%s\n' "$files" | grep -c '[^[:space:]]' || true)
if [ "$count" -eq 0 ]; then
    echo "locale: scanned 0 files -- the check is broken, which is not a pass" >&2
    exit 1
fi

# The wide variants and the case-insensitive string compares fold per LC_CTYPE
# too. isxdigit/ispunct are plausible additions to an XML scanner.
# The prefix class excludes `.` and `>` so a member call (obj.isspace, p->isspace)
# is not a false positive. It must NOT exclude `:`: that is the character before
# the name in EVERY qualified call — `::tolower(`, `std::tolower(`,
# `std::isspace(` — so excluding it made the guard blind to the exact form the
# original defect took (`::toupper`) and the form this branch removed from
# client.cpp (`::tolower`). Measured: 1 of 4 calls matched with `:` excluded,
# 4 of 4 without it.
pattern='(^|[^[:alnum:]_.>])(isalpha|isalnum|isupper|islower|isspace|isdigit|isxdigit|ispunct|isprint|isblank|iscntrl|isgraph|toupper|tolower|towupper|towlower|strcasecmp|strncasecmp)[[:space:]]*\('

fail=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Strip // line comments and /* */ block comments before matching: these
    # files EXPLAIN why the calls are avoided, and a check that trips on its own
    # rationale gets deleted. A naive `s://.*::` also truncates at the // inside
    # a URL literal, hiding real code after it — so block comments are removed
    # first and the line-comment strip requires whitespace or start-of-line
    # before the slashes.
    stripped=$(perl -0pe 's{/\*.*?\*/}{}gs; s{(^|\s)//.*$}{$1}gm' "$f")
    if printf '%s' "$stripped" | grep -nE "$pattern" >/dev/null 2>&1; then
        echo "locale: $f calls a locale-sensitive ctype function" >&2
        printf '%s' "$stripped" | grep -nE "$pattern" | sed 's/^/    /' >&2
        fail=1
    fi
done < <(printf '%s\n' "$files")

if [ "$fail" != 0 ]; then
    echo "" >&2
    echo "Use an ASCII-only comparison. Syntax on this path is ASCII by definition." >&2
    exit 1
fi
echo "locale: $count protocol file(s), none locale-dependent"
