---
title: Getting started
---

## Install

```sql
INSTALL xmla FROM community;
LOAD xmla;
```

Linux is the supported platform. macOS builds locally but is not
redistributable, and Windows is not a target — see
[Building](./development.md).

## What you need from the server

- **A pinned port.** There is no named-instance redirector: the service on TCP
  2382 has no public specification and was verified empirically not to speak the
  `[MC-SQLR]` framing that resolves database-engine instances. Pin the port in
  `msmdsrv.ini`. A firewall rule is needed either way, so pinning costs the
  operator nothing, and a wrong guess presents as a hang rather than an error.
- **A read-only account.** See [Read-only](./index.md#read-only-deliberately).
- **Kerberos or NTLM.** Kerberos is what a domain deployment uses and is the
  default; NTLM is what a standalone workgroup server can do.

## A first query

Credentials never go in the connection string — that string reaches the query
log and the query plan. Put them in a secret:

```sql
CREATE SECRET ssas (TYPE xmla, MECHANISM 'ntlm', USER '...', PASSWORD '...');
```

With a Kerberos ticket in the cache, supply nothing at all and the ambient
identity is used.

Then either attach the instance as a database:

```sql
ATTACH 'host=ssas-host port=2383 secret=ssas' AS aw (TYPE xmla);
SHOW ALL TABLES;
```

or call the table functions directly, which needs no `ATTACH`:

```sql
SELECT CUBE_NAME, CUBE_TYPE
FROM xmla_discover('host=ssas-host port=2383 secret=ssas', 'MDSCHEMA_CUBES');
```

## Which path to take

The two model kinds are genuinely different, and the extension does not pretend
otherwise:

- A **tabular** model has tables and DAX. `ATTACH` it and use `SELECT`; see
  [Tabular models](./tabular.md).
- A **multidimensional** model has cubes, dimensions and measure groups, and is
  queried with MDX. Its metadata lists, but its rows cannot be read as tables;
  see [Cubes and MDX](./cubes.md).

## Verifying reachability

`ATTACH` deliberately contacts nothing — schemas load on first use, so attaching
an unreachable instance succeeds and the first query reports the failure. To test
the connection itself, run a discovery call:

```sql
SELECT * FROM xmla_discover('host=ssas-host port=2383 secret=ssas',
                            'DISCOVER_DATASOURCES');
```

If that fails, [Troubleshooting](./reference/troubleshooting.md) lists the
failure modes that look like something else.
