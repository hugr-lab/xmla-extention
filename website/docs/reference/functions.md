---
title: Functions
---

Two table functions, plus the catalog surface `ATTACH` provides. Together they
already exceed what the Windows-only `msolap` extension offers, which provides
one function and no way to ask for metadata at all.

## `xmla_discover`

```sql
xmla_discover(connection, request_type
              [, catalog := ...] [, secret := ...] [, restrictions := ...])
```

Runs an XMLA `Discover` and returns its rowset. Column names and order are the
server's.

```sql
SELECT CUBE_NAME, CUBE_TYPE
FROM xmla_discover('host=h port=2383 secret=ssas', 'MDSCHEMA_CUBES',
                   catalog := 'My Model');
```

`restrictions` is a `MAP`, so the names are data rather than SQL text. Each name
is validated against the XMLA rowset column shape and anything else is
**refused** — an element name cannot be made safe by escaping:

```sql
SELECT COLUMN_NAME, DATA_TYPE
FROM xmla_discover('secret=ssas', 'DBSCHEMA_COLUMNS',
                   catalog := 'My Model',
                   restrictions := MAP {'TABLE_NAME': 'DimProduct'});
```

Useful request types:

| request type | what it answers |
|---|---|
| `DISCOVER_DATASOURCES` | is the instance reachable and who am I |
| `DBSCHEMA_CATALOGS` | which models does this instance hold |
| `DBSCHEMA_TABLES` | tables of a tabular model |
| `DBSCHEMA_COLUMNS` | their columns |
| `MDSCHEMA_CUBES` | "show all cubes" |
| `MDSCHEMA_MEASURES` | measures and their measure groups |
| `MDSCHEMA_DIMENSIONS` | dimensions and cardinalities |
| `MDSCHEMA_HIERARCHIES` | hierarchies per dimension |
| `MDSCHEMA_LEVELS` | levels per hierarchy |

`TMSCHEMA_*` rowsets exist but require **administrator** rights, so a read-only
account cannot call them.

## `xmla_execute`

```sql
xmla_execute(connection, statement [, catalog := ...] [, secret := ...])
```

Sends a read-only analytic statement — DAX for a tabular model, MDX for a cube —
and returns rows. The client asks for `Format=Tabular`, so an MDX cellset is
flattened; see [Cubes and MDX](../cubes.md).

```sql
SELECT * FROM xmla_execute('secret=ssas', 'EVALUATE TOPN(10, Sales)',
                           catalog := 'My Model');
```

The statement is **validated before any connection is opened**. Anything whose
first significant keyword is not `SELECT`, `EVALUATE`, `WITH`, `DEFINE` or `VAR`
is refused as a binder error, and so is a statement batch — a separator followed
by more text is refused even when the first keyword is a query keyword, because
SSMS sends semicolon-separated MDX as a single `Execute`.

## `ATTACH`

```sql
ATTACH '<connection string>' AS <name> (TYPE xmla [, SECRET ...] [, CATALOG ...]);
```

Presents the instance as a database whose schemas are its models. `SHOW ALL
TABLES`, `DESCRIBE` and `SELECT` then work through DuckDB's own commands — the
extension implements none of them.

`ATTACH` contacts nothing: schemas load on first use, so attaching an
unreachable instance succeeds and the first query reports the failure. That is a
deliberate difference from the neighbouring `mssql` extension's eager
validation — an instance powered off between sessions would otherwise make every
`ATTACH` in a script fail, even for a catalog the script never touches.

Known `ATTACH` options are `TYPE`, `SECRET` and `CATALOG`. Anything else is
refused rather than ignored.

## Secrets

```sql
CREATE SECRET <name> (
    TYPE xmla,
    HOST '...', PORT 2383,
    MECHANISM 'ntlm' | 'kerberos' | 'negotiate',
    USER '...', PASSWORD '...', SPN '...'
);
```

An unknown field is refused rather than stored and ignored — a misspelled
`PASSWRD` would otherwise leave the secret silently without one. `PASSWORD` is
redacted in `duckdb_secrets()`.
