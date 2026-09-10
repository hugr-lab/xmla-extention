---
title: Tabular models
---

A tabular model has tables and DAX, so it maps onto SQL directly. `ATTACH` it
and the instance's models become schemas, their tables become tables.

Everything below is a real transcript against a live SQL Server 2022 tabular
instance. Only the host, account and password are replaced; the catalog on that
instance is called `AWTabular`.

```sql
CREATE SECRET ssas (TYPE xmla, HOST '<instance>', PORT 2383,
                    MECHANISM 'ntlm', USER '<user>', PASSWORD '<password>');
ATTACH 'secret=ssas' AS aw (TYPE xmla);
```

## Listing

`SHOW ALL TABLES` is DuckDB's own command — the extension implements neither it
nor `DESCRIBE`. They work because the catalog presents schemas and tables:

```sql
SHOW ALL TABLES;
```

```
┌──────────┬───────────┬───────────────────┬──────────────────────────────────────────┬─────────────────────────────┬───────────┐
│ database │  schema   │       name        │               column_names               │        column_types         │ temporary │
├──────────┼───────────┼───────────────────┼──────────────────────────────────────────┼─────────────────────────────┼───────────┤
│ aw       │ AWTabular │ DimProduct        │ [ProductKey, EnglishProductName]         │ [VARCHAR, VARCHAR]          │ false     │
│ aw       │ AWTabular │ FactInternetSales │ [ProductKey, SalesAmount, OrderQuantity] │ [VARCHAR, VARCHAR, VARCHAR] │ false     │
└──────────┴───────────┴───────────────────┴──────────────────────────────────────────┴─────────────────────────────┴───────────┘
```

```sql
DESCRIBE aw."AWTabular".DimProduct;
```

```
┌────────────────────┬─────────────┬──────┬──────┬─────────┬───────┐
│    column_name     │ column_type │ null │ key  │ default │ extra │
├────────────────────┼─────────────┼──────┼──────┼─────────┼───────┤
│ ProductKey         │ VARCHAR     │ YES  │ NULL │ NULL    │ NULL  │
│ EnglishProductName │ VARCHAR     │ YES  │ NULL │ NULL    │ NULL  │
└────────────────────┴─────────────┴──────┴──────┴─────────┴───────┘
```

Only user tables are listed. `DBSCHEMA_TABLES` on a tabular model returns three
populations and only one of them is a table anyone wants: 123 rows of `SCHEMA`
in `$SYSTEM` (the server's own introspection rowsets), a `SYSTEM TABLE` per
measure group, and the `TABLE` rows that hold real columns. Listing everything
filled `SHOW ALL TABLES` with the server's introspection surface, so the catalog
takes `TABLE_TYPE = 'TABLE'` only, strips SSAS's internal `$` prefix, and drops
the `RowNumber-<GUID>` surrogate that `EVALUATE` does not return.

## The point of the whole thing

The SSAS side is an ordinary scan, so it joins, filters and aggregates like any
other table:

```sql
CREATE TABLE local_notes(k VARCHAR, note VARCHAR);
INSERT INTO local_notes VALUES ('310','discontinued'),
                               ('311','review pricing'),
                               ('312','low stock');

SELECT p.EnglishProductName, local.note
FROM aw."AWTabular".DimProduct p
JOIN local_notes local ON p.ProductKey = local.k
ORDER BY p.EnglishProductName;
```

```
┌────────────────────┬────────────────┐
│ EnglishProductName │      note      │
├────────────────────┼────────────────┤
│ Road-150 Red, 44   │ review pricing │
│ Road-150 Red, 48   │ low stock      │
│ Road-150 Red, 62   │ discontinued   │
└────────────────────┴────────────────┘
```

## How a scan behaves

A `SELECT` **streams**. The protocol layer hands back a cursor rather than a
whole rowset, so rows are decoded as records arrive and a query that stops
asking stops the transfer.

**The projection is pushed down.** A narrow `SELECT` sends a DAX
`SELECTCOLUMNS` list rather than the whole table. That needs a tabular model at
compatibility level 1200 or above (SSAS 2016+), which is **unverified** against
anything older, so it is used only when it actually narrows the transfer — a
`SELECT *` still sends plain `EVALUATE '<table>'`.

**`LIMIT` works by stopping the read**, not by a DAX clause. DuckDB v2.0 passes
no limit to a table scan at all: `TableFunctionInitInput` carries the
projection, the filters and the sample options, and has no field for a limit. So
the scan cannot ask the server for five rows — what it can do is abandon the
response, and it does.

Measured on a 60398-row fact table with three columns:

| query | DAX sent | wall clock |
|---|---|---|
| all 3 columns, whole table | `EVALUATE 'T'` | 37.07 s |
| 1 of 3 columns, whole table | `EVALUATE SELECTCOLUMNS(…)` | 2.22 s |
| all 3 columns, `LIMIT 5` | `EVALUATE 'T'`, abandoned early | 0.27 s |

The `WHERE` clause is **not** pushed down, and that is a measurement rather than
an omission — see [Limitations](./reference/limitations.md).

## Types

Everything arrives as `VARCHAR`. The rowset that is supposed to report a
column's type reports `WSTR` for all of them, so a real type mapping needs a
different source, and guessing a type from a value would not be honest. Cast in
SQL:

```sql
SELECT sum(CAST(SalesAmount AS DOUBLE)) FROM aw."AWTabular".FactInternetSales;
```

## Ad-hoc DAX

`xmla_execute` sends a statement and hands back rows, with no `ATTACH` needed:

```sql
SELECT * FROM xmla_execute('secret=ssas', 'EVALUATE TOPN(3, FactInternetSales)',
                           catalog := 'AWTabular');
```

```
┌───────────────────────────────┬────────────────────────────────┬──────────────────────────────────┐
│ FactInternetSales[ProductKey] │ FactInternetSales[SalesAmount] │ FactInternetSales[OrderQuantity] │
├───────────────────────────────┼────────────────────────────────┼──────────────────────────────────┤
│ 477                           │ 4.99                           │ 1                                │
│ 477                           │ 4.99                           │ 1                                │
│ 477                           │ 4.99                           │ 1                                │
└───────────────────────────────┴────────────────────────────────┴──────────────────────────────────┘
```

`EVALUATE` **qualifies its result columns** as `<table>[<column>]`, which is
why those headers look like that. A scan looking up the bare name misses every
row and returns all-NULL — which is exactly what the first working `ATTACH` did,
so the mapping now accepts the qualified name, the bare name and the bracketed
alias form.
