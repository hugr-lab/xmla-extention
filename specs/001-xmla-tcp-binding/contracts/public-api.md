# Public API contract

Everything a DuckDB user can reach. Nothing here mutates server state, and nothing here is a
gate over a mutating capability — the capability does not exist (FR-028).

## ATTACH

    ATTACH 'host=<host> port=<port>' AS <alias> (TYPE xmla);

Connection-string keys:

| key | required | meaning |
|---|---|---|
| `host` | yes | instance hostname or address |
| `port` | yes | pinned port. No default; see research D9 |
| `mechanism` | no | `kerberos` (default), `negotiate`, `ntlm` |
| `user` | no | principal. Omitted means the ambient identity |
| `catalog` | no | restrict the attached catalog to one model |
| `spn` | no | full SPN override, service class included |
| `instance` | no | named-instance SPN form |
| `use_port` | no | ask for the `MSOLAPSvc.3/host:port` SPN form |
| `timeout` | no | seconds; must be positive |

A password is never taken from the connection string. It comes from a DuckDB secret or the
environment, so it cannot end up in a query log.

## Catalog surface

The attached catalog presents the instance's catalogs as schemas and their tables as tables.
`SHOW`/`DESCRIBE` and reads work. DDL and DML raise — not because they are blocked, but
because no path to them is registered.

## Table functions

    xmla_discover(<alias>, '<REQUEST_TYPE>' [, restrictions := {...}] [, catalog := '...'])
    xmla_execute (<alias>, '<statement>' [, catalog := '...'])

`xmla_discover` is the general metadata request; `DISCOVER_DATASOURCES`, `DBSCHEMA_CATALOGS`,
`DBSCHEMA_TABLES` and `DBSCHEMA_COLUMNS` are the ones the catalog layer itself uses.

Restriction **names** are validated against the XMLA rowset column shape rather than escaped:
an element name cannot be made safe by escaping, so an invalid one is rejected. Restriction
**values** are escaped.

`xmla_execute` runs a read-only analytic statement. There is no builder for a mutating
command anywhere in the envelope layer, so no argument to this function can reach one.

## Errors

Six categories (see data-model.md). No message contains a hostname, address, account name,
realm, SPN, machine name or security identifier.
