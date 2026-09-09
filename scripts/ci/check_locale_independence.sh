#!/usr/bin/env bash
# The wire path must not depend on the process locale.
#
# A DuckDB extension is loaded into a host process that may have called
# setlocale(LC_CTYPE, "") — CPython does, and so does R. Under tr_TR.UTF-8,
# toupper('i') is not 'I', so a lower-case "with member ... select ..." folds to
# "WiTH", misses the query allowlist, and a legitimate query is refused. Keyword
# and identifier syntax here is ASCII by definition, so the locale has no
# business in it.
#
# This check exists because a source edit meant to fix exactly that silently did
# not apply: the replacement no longer matched after the file was reformatted,
# the ASCII helpers were left with no call sites, and the locale-bound calls
# stayed. The unit test could not catch it either — it tries to switch to
# tr_TR.UTF-8 and that locale is not installed on every machine, so it passed
# without demonstrating anything. CodeQL found it, as "unused static function".
#
# A grep is a blunt instrument, but it is deterministic and it fails on the
# exact shape that regressed.
set -euo pipefail

# Files that build XMLA on the wire. Their parsing decides what reaches a server.
targets="src/xmla/envelopes.cpp src/xmla/rowset.cpp"

pattern='(^|[^[:alnum:]_])(isalpha|isalnum|isupper|islower|isspace|isdigit|toupper|tolower)[[:space:]]*\('

fail=0
for f in $targets; do
    if [ ! -f "$f" ]; then
        echo "locale: $f does not exist -- the check is stale, which is not a pass" >&2
        exit 1
    fi
    # Strip comments before matching: the files explain WHY these are avoided,
    # and a check that trips on its own rationale gets deleted.
    if sed 's://.*::' "$f" | grep -nE "$pattern" >/dev/null 2>&1; then
        echo "locale: $f calls a locale-sensitive ctype function" >&2
        sed 's://.*::' "$f" | grep -nE "$pattern" | sed 's/^/    /' >&2
        fail=1
    fi
done

if [ "$fail" != 0 ]; then
    echo "" >&2
    echo "Use the ASCII helpers (AsciiAlpha/AsciiUpper/AsciiSpace) instead. Keyword and" >&2
    echo "identifier syntax on this path is ASCII by definition." >&2
    exit 1
fi
echo "locale: $(echo $targets | wc -w | tr -d ' ') wire-path file(s), none locale-dependent"
