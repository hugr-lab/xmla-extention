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

# The security dependency does not only arrive as <gssapi/...>. krb5.h and
# com_err.h are the other doors into the same library, so "free of GSSAPI" has
# to name them too or it is narrower than it claims.
security_pattern='#include[[:space:]]*[<"](gssapi|krb5|com_err)'
duckdb_pattern='#include[[:space:]]*[<"]duckdb'

# ONE find, captured once, so the set that is scanned and the set that is counted
# cannot diverge.
files=$(find src/xmla src/include/xmla \( -name '*.cpp' -o -name '*.hpp' \) -print)

# A file list that came back empty is a broken check, not a pass.
count=$(printf '%s\n' "$files" | grep -c '[^[:space:]]' || true)
if [ "$count" -eq 0 ]; then
    echo "layering: scanned 0 files -- the check is broken, which is not a pass" >&2
    exit 1
fi

while IFS= read -r f; do
    [ -n "$f" ] || continue
    # gss_context.cpp is the ONE file allowed to bind GSSAPI, and it lives in its
    # own CMake target for that reason. The exemption covers the SECURITY half
    # only -- it is not a licence to include DuckDB there.
    if [ "$f" != "src/xmla/gss_context.cpp" ]; then
        if grep -nE "$security_pattern" "$f" >/dev/null 2>&1; then
            echo "layering: $f includes a GSSAPI/krb5 header" >&2
            grep -nE "$security_pattern" "$f" | sed 's/^/    /' >&2
            fail=1
        fi
    fi
    if grep -nE "$duckdb_pattern" "$f" >/dev/null 2>&1; then
        echo "layering: $f includes a DuckDB header" >&2
        grep -nE "$duckdb_pattern" "$f" | sed 's/^/    /' >&2
        fail=1
    fi
done < <(printf '%s\n' "$files")

if [ "$fail" != 0 ]; then
    echo "" >&2
    echo "The protocol layer must stay free of both. Put the binding in" >&2
    echo "src/xmla/gss_context.cpp, or above the protocol layer entirely." >&2
    exit 1
fi
echo "layering: $count protocol files, none including DuckDB, GSSAPI, krb5 or com_err"
