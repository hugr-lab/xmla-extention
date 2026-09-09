#!/usr/bin/env bash
# The protocol layer's isolation, enforced rather than reviewed.
#
# src/xmla/ must include no DuckDB header and no GSSAPI header. That is what
# makes constitution III's "passes on a machine that has never contacted an
# Analysis Services instance" achievable -- and that machine may equally never
# have had a Kerberos library on it.
#
# The linker already catches the GSSAPI half (xmla_protocol links no security
# library, so a stray call fails to link). This catches the include before the
# link does, and says WHY rather than printing an undefined symbol.
set -euo pipefail

fail=0

# gss_context.cpp is the ONE file allowed to bind GSSAPI, and it lives in its own
# CMake target for that reason.
while IFS= read -r f; do
    case "$f" in
        src/xmla/gss_context.cpp) continue ;;
    esac
    if grep -nE '#include[[:space:]]*[<"](duckdb|gssapi)' "$f" >/dev/null 2>&1; then
        echo "layering: $f includes a DuckDB or GSSAPI header" >&2
        grep -nE '#include[[:space:]]*[<"](duckdb|gssapi)' "$f" | sed 's/^/    /' >&2
        fail=1
    fi
done < <(find src/xmla src/include/xmla -name '*.cpp' -o -name '*.hpp')

# A file list that came back empty is a broken check, not a pass.
count=$(find src/xmla src/include/xmla -name '*.cpp' -o -name '*.hpp' | grep -c '' || true)
if [ "$count" -eq 0 ]; then
    echo "layering: scanned 0 files -- the check is broken, which is not a pass" >&2
    exit 1
fi

if [ "$fail" != 0 ]; then
    echo "" >&2
    echo "The protocol layer must stay free of both. Put the binding in" >&2
    echo "src/xmla/gss_context.cpp, or above the protocol layer entirely." >&2
    exit 1
fi
echo "layering: $count protocol files, none including DuckDB or GSSAPI"
