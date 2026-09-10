---
title: xmla
sidebar_label: Overview
slug: /
---

A DuckDB extension that reads **SQL Server Analysis Services** over the native
**XMLA/TCP** binding — from Linux, with no IIS, no `msmdpump`, no COM and no
Windows components anywhere in the path.

```sql
INSTALL xmla FROM community;
LOAD xmla;

CREATE SECRET ssas (TYPE xmla, MECHANISM 'ntlm', USER 'reader', PASSWORD '...');
ATTACH 'host=ssas-host port=2383 secret=ssas' AS aw (TYPE xmla);

SHOW ALL TABLES;
SELECT * FROM aw."My Model".DimProduct LIMIT 10;
```

## Why it exists

SSAS speaks XMLA over two bindings. One is HTTP through the `msmdpump` ISAPI
extension hosted in IIS; the other is a native TCP binding. Every existing
client for the native one is Windows-only — ADOMD.NET and the MSOLAP OLE DB
provider are COM/.NET, and DuckDB's own `msolap` extension states Windows-only
support because of those COM dependencies. A Linux consumer that wants SSAS data
has therefore had to stand up IIS in front of every instance.

This extension removes that requirement. It is named for the wire protocol
rather than for a product, because the same protocol serves SSAS, Azure Analysis
Services and Power BI Premium endpoints — and because naming it after a provider
DLL would misdescribe an implementation that uses no provider at all.

## What works

| | |
|---|---|
| NTLM, end to end | **works**, verified against SQL Server 2022 on tabular and multidimensional instances |
| `ATTACH`, `SHOW ALL TABLES`, `DESCRIBE`, `SELECT` | **works** on a tabular model |
| MDX against a cube, via `xmla_execute` | **works** — the client asks for `Format=Tabular`, so a cellset arrives as rows |
| Metadata (`MDSCHEMA_*`, `DBSCHEMA_*`, `DISCOVER_*`) | **works** — ordinary table functions, so they join |
| Projection pushdown | **works** — a narrow `SELECT` sends a DAX `SELECTCOLUMNS` list, not the whole table |
| `LIMIT` | **works** by stopping the read; DuckDB passes no limit to a scan |
| Filter pushdown | not done — see [Limitations](./reference/limitations.md) |
| `SELECT` on a multidimensional model | not supported — row scans need DAX; use [MDX](./cubes.md) |
| Kerberos | **unverified against a live server** — see [Authentication](./protocol/authentication.md) |
| Linux | supported |
| macOS | local build only, needs MIT krb5 |
| Windows | not a target — you already have `msolap` |

## Read-only, deliberately

Two different guarantees, and the difference matters:

- **Metadata is read-only by construction.** No envelope builder for a mutating
  command exists, so no argument to any discovery function can reach one.
- **Statements are read-only by validation.** `xmla_execute` refuses anything
  whose first significant keyword is not `SELECT`, `EVALUATE`, `WITH`, `DEFINE`
  or `VAR`, and refuses a statement batch. This is needed because XMLA's
  `<Statement>` element carries the *whole* command surface — MDX writeback
  (`UPDATE CUBE`), DMX (`INSERT INTO`, `DROP MINING MODEL`) and stored-procedure
  `CALL` all travel through it.

The second is a guard, not a proof. **Grant the connecting account read-only
permissions on the server.** That is the only control that cannot be reasoned
around, and no client-side check substitutes for it.

## The mascot

A **lesser scaup**: a diving duck, because drilling into a cube is diving, not
dabbling.
