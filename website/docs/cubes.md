---
title: Cubes and MDX
---

A multidimensional model has cubes, dimensions and measure groups, and is
queried with MDX. Its metadata lists like any other, but its rows cannot be read
as tables — reading rows needs `EVALUATE`, which is DAX, and a multidimensional
model has no DAX.

Everything below is a real transcript against a live SQL Server 2022
multidimensional instance. Only the host, account and password are replaced.

```sql
CREATE SECRET md (TYPE xmla, HOST '<instance>', PORT 2384,
                  MECHANISM 'ntlm', USER '<user>', PASSWORD '<password>');
```

## What cubes are there

`MDSCHEMA_CUBES` is "show all cubes":

```sql
SELECT CUBE_NAME, CUBE_TYPE, LAST_SCHEMA_UPDATE
FROM xmla_discover('secret=md', 'MDSCHEMA_CUBES', catalog := 'AWMultidim');
```

```
┌───────────┬───────────┬────────────────────────────┐
│ CUBE_NAME │ CUBE_TYPE │     LAST_SCHEMA_UPDATE     │
├───────────┼───────────┼────────────────────────────┤
│ AWCube    │ CUBE      │ 2026-08-19T18:20:52.233333 │
└───────────┴───────────┴────────────────────────────┘
```

## What is in it

These are ordinary table functions, so they join:

```sql
SELECT MEASURE_NAME, MEASURE_UNIQUE_NAME, MEASUREGROUP_NAME, DATA_TYPE
FROM xmla_discover('secret=md', 'MDSCHEMA_MEASURES', catalog := 'AWMultidim');

SELECT h.HIERARCHY_UNIQUE_NAME, l.LEVEL_NAME, l.LEVEL_NUMBER, l.LEVEL_CARDINALITY
FROM xmla_discover('secret=md', 'MDSCHEMA_LEVELS', catalog := 'AWMultidim') l
JOIN xmla_discover('secret=md', 'MDSCHEMA_HIERARCHIES', catalog := 'AWMultidim') h
  ON h.HIERARCHY_UNIQUE_NAME = l.HIERARCHY_UNIQUE_NAME
ORDER BY l.LEVEL_UNIQUE_NAME;
```

```
┌──────────────┬───────────────────────────┬───────────────────┬───────────┐
│ MEASURE_NAME │    MEASURE_UNIQUE_NAME    │ MEASUREGROUP_NAME │ DATA_TYPE │
├──────────────┼───────────────────────────┼───────────────────┼───────────┤
│ Sales Amount │ [Measures].[Sales Amount] │ Internet Sales    │ 6         │
└──────────────┴───────────────────────────┴───────────────────┴───────────┘

┌─────────────────────────┬───────────────┬──────────────┬───────────────────┐
│  HIERARCHY_UNIQUE_NAME  │  LEVEL_NAME   │ LEVEL_NUMBER │ LEVEL_CARDINALITY │
├─────────────────────────┼───────────────┼──────────────┼───────────────────┤
│ [Measures]              │ MeasuresLevel │ 0            │ 1                 │
│ [Product].[Product Key] │ (All)         │ 0            │ 1                 │
│ [Product].[Product Key] │ Product Key   │ 1            │ 607               │
└─────────────────────────┴───────────────┴──────────────┴───────────────────┘
```

`MDSCHEMA_DIMENSIONS` and `MDSCHEMA_MEMBERS` work the same way. See
[Functions](./reference/functions.md) for the full set.

## Querying with MDX

```sql
SELECT * FROM xmla_execute('secret=md',
  'SELECT {[Measures].[Sales Amount]} ON COLUMNS,
          TOPCOUNT([Product].[Product Key].[Product Key].MEMBERS, 5,
                   [Measures].[Sales Amount]) ON ROWS
   FROM [AWCube]', catalog := 'AWMultidim');
```

```
┌────────────────────────────────────────────────────────┬───────────────────────────┐
│ [Product].[Product Key].[Product Key].[MEMBER_CAPTION] │ [Measures].[Sales Amount] │
├────────────────────────────────────────────────────────┼───────────────────────────┤
│ Road-150 Red, 48                                       │ 1205876.99                │
│ Road-150 Red, 62                                       │ 1202298.72                │
│ Road-150 Red, 52                                       │ 1080637.54                │
│ Road-150 Red, 56                                       │ 1055589.65                │
│ Road-150 Red, 44                                       │ 1005493.87                │
└────────────────────────────────────────────────────────┴───────────────────────────┘
```

:::note Why `Format=Tabular` matters

An MDX result is a **cellset** — axes and cells — not a rowset. Execute's default
`Format` is `Multidimensional`, and under it this client found no `<row>` in the
response and reported an **empty result**. Since an empty rowset is a meaningful
answer here ("no rows visible to this account"), every MDX query against every
cube looked like an empty cube, with no error at all.

The client now sends `Format=Tabular` and the server flattens the cellset into
rows. If a server ever ignores the property, both read paths refuse the response
rather than reporting it as empty.
:::

MDX is DAX's sibling, not its dialect: `TOPN` is DAX and `TOPCOUNT` is MDX, and
the server will tell you so.

## `SELECT` on a cube is refused

```sql
ATTACH 'secret=md catalog=AWMultidim' AS cube (TYPE xmla);
SELECT * FROM cube.AWMultidim.Product LIMIT 3;
-- Not implemented Error: xmla: 'Product' is in a multidimensional model, whose
-- rows cannot be read as a table. Multidimensional data is queried with MDX —
-- use xmla_execute() — while a tabular model's tables support SELECT directly.
```

That refusal is deliberate rather than a gap to fill later. Sending a DAX
statement a multidimensional server will reject would produce an error the user
cannot act on; naming MDX and `xmla_execute` is actionable.

`SHOW ALL TABLES` still lists the table with its columns, because that needs no
scan. `DESCRIBE` does not, because DuckDB binds a scan to answer it.

## Reading the output

Two things are worth knowing before building on this, because both are the
server's shape rather than a choice made here.

**MDX result columns keep their MDX unique names.**
`[Product].[Product Key].[Product Key].[MEMBER_CAPTION]` is what the flattened
cellset calls that column, and renaming it would mean guessing which part the
caller wanted. Alias it in SQL:

```sql
SELECT "[Product].[Product Key].[Product Key].[MEMBER_CAPTION]" AS product,
       "[Measures].[Sales Amount]"                             AS sales
FROM xmla_execute(...);
```

**Some metadata columns are raw OLE DB codes.** `DATA_TYPE` is `6` for that
measure (currency); `DIMENSION_TYPE` is `2` for `[Measures]` and `3` for
`[Product]`. They are passed through as the server sent them: decoding them
means shipping a table of enumeration values, and this project does not state a
protocol claim it has not verified. `CUBE_TYPE` arrives as text because the
server sends it that way.
