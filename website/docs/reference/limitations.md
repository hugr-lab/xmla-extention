---
title: Limitations
---

Each of these is a measurement or a decision with a reason, not a to-do list
with the reasons omitted.

## Filter pushdown is not done

`WHERE` is applied by DuckDB, not by the server. It was implemented and the live
instance refused it. The obvious rendering of `WHERE ProductKey = '477'` is

```
FILTER('FactInternetSales', 'FactInternetSales'[ProductKey] = "477")
```

and the server answers:

> DAX comparison operations do not support comparing values of type Integer with
> values of type Text. Consider using the VALUE or FORMAT function to convert
> one of the values.

Every column this extension presents is `VARCHAR`, so a rendered constant is
always a DAX **text** literal, and DAX refuses the comparison against a numeric
column rather than coercing it. The error carries a query position, so it is
raised when the expression is analysed — `IFERROR` cannot absorb it.

Knowing the column's real type would settle it, and no non-admin path provides
it (both measured against SQL Server 2022):

- `DBSCHEMA_COLUMNS` reports `DATA_TYPE = 130` (`DBTYPE_WSTR`) for **every**
  column of a tabular model, including the one DAX calls Integer. It cannot tell
  them apart.
- `TMSCHEMA_COLUMNS`, which does carry `ExplicitDataType`, is refused: *"needs
  to be an administrator to read the metadata of the database"*. Asking for
  administrator rights to read a column type contradicts the read-only stance.

A type-agnostic rendering does not exist either. `CONVERT(c, STRING)` and
`CONTAINSSTRING` both push the comparison through DAX's own number-to-text
formatting, which need not match the rendering XMLA puts in the rowset — and a
mismatch **drops rows** DuckDB would have kept, which is the one failure mode
that is silent. A loud DAX error is bad; a quietly short answer is worse.

## Every column is VARCHAR

For the same reason: the rowset that is supposed to report a column's type
reports `WSTR` for all of them. `DISCOVER_CSDL_METADATA`, which a reader *can*
call, is the candidate for a real type mapping.

## Limit pushdown is not expressible

DuckDB v2.0 passes no limit to a table function: `TableFunctionInitInput` carries
the projection, the filters and the sample options, and has no field for a limit.
So a scan cannot ask the server for five rows. What it does instead is stop
reading — destroying the cursor abandons the response rather than draining it, so
the remaining bytes are never transferred. `LIMIT 5` over a 60398-row table takes
0.27 s against 37.07 s for the full scan.

## Multidimensional models cannot be scanned

Reading rows needs `EVALUATE`, which is DAX; a multidimensional model is queried
with MDX over cubes, dimensions and measure groups. The catalog reports its
metadata and refuses the row scan with a message naming MDX and `xmla_execute`.
`DESCRIBE` is refused too, because DuckDB binds a scan to answer it — the columns
are still visible through `SHOW ALL TABLES`.

## `SELECTCOLUMNS` needs SSAS 2016+

Projection pushdown uses `SELECTCOLUMNS`, which needs a tabular model at
compatibility level 1200 or above. That floor is **unverified** — no older
instance is available to this project — which is why the projection is sent only
when it actually narrows the transfer, leaving `SELECT *` on the plain
`EVALUATE '<table>'` path that has been exercised live since the first working
scan.

## Kerberos is unverified against a live server

See [Authentication](../protocol/authentication.md#kerberos). The
mechanism-level questions are settled against a real MIT KDC; what is not
settled needs a domain-joined instance.

## Binary XML and compression are not implemented

Both are optional in the protocol, so this client requests neither. A server that
selects one anyway is refused loudly rather than absorbed — a refusal there is a
scope change to report, not a fallback.

## macOS builds are not redistributable

Apple's `GSS.framework` exports no `gss_wrap_iov` and ships no NTLM mechanism, so
MIT krb5 from Homebrew is the only option. It is keg-only and ships no static
archives, so the extension records the dylibs' install names verbatim — `otool
-L` shows `/opt/homebrew/opt/krb5/lib/libgssapi_krb5.2.2.dylib` — and the
artifact loads only where that prefix is populated. macOS is therefore excluded
from the community-registry platforms and supported as a local build.

## Windows is not a target

You already have `msolap`, and the point of this extension is to reach SSAS
without COM.
