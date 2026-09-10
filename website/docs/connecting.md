---
title: Connecting
---

## The connection string

Space-separated `key=value` pairs. Keys are case-insensitive; an **unknown key
is an error** rather than being ignored, because a silently dropped
`mechanism=ntlm` authenticates with something the caller did not ask for.

```sql
ATTACH 'host=ssas-host port=2383 mechanism=kerberos' AS aw (TYPE xmla);
```

See [Options](./reference/options.md) for the full list.

## Secrets

A password may not travel in a connection string, and the extension refuses one
that does. Use a secret:

```sql
CREATE SECRET ssas (
    TYPE xmla,
    HOST 'ssas-host',
    PORT 2383,
    MECHANISM 'ntlm',
    USER '...',
    PASSWORD '...'
);

ATTACH 'secret=ssas' AS aw (TYPE xmla);
```

Every field except the password can come from either place. **The connection
string wins over the secret**, and the default is applied last — so a secret
carrying `mechanism='ntlm'` beats the `kerberos` default, which is the whole
reason the order is fixed in one place rather than left to callers.

The password is read at the moment a session opens and handed straight to the
security layer. It is never stored on anything a caller holds, printed, or
serialised into a plan, and `duckdb_secrets()` shows it as `redacted`.

## Ambient identity

With no `USER` and no `PASSWORD`, the process's own Kerberos credentials are
used:

```sql
CREATE SECRET ssas (TYPE xmla, MECHANISM 'kerberos');
```

Failure to find a ticket is reported as an authentication problem, not as a
connection one.

## Which SPN is used

Kerberos needs a service principal name for the instance. By default the
extension builds the portless form GSSAPI produces, `MSOLAPSvc.3/<host>`. Two
options change it:

```sql
-- a named instance
ATTACH 'host=h port=2383 instance=TAB' AS aw (TYPE xmla);
-- the port-suffixed form ADOMD's DsMakeSpn produces
ATTACH 'host=h port=2383 use_port=true' AS aw (TYPE xmla);
-- or say it outright
ATTACH 'host=h port=2383 spn=MSOLAPSvc.3/host.example:2383' AS aw (TYPE xmla);
```

Which form a production instance actually registers is **unverified** — NTLM
ignores the target entirely, which is why the portless form has worked so far
and proves nothing about Kerberos.

## Read-only attachments

An attachment is read-only and cannot be made otherwise. An explicit
`READ_ONLY false` (or `READ_WRITE true`) is **refused** rather than quietly
downgraded, because the caller asked for something the extension cannot provide:

```sql
ATTACH 'host=h port=2383' AS aw (TYPE xmla, READ_ONLY false);
-- Binder Error: xmla: an Analysis Services attachment is read-only;
-- remove READ_ONLY from the ATTACH options
```

Not specifying anything is not a request, so a plain `ATTACH` succeeds and the
attachment reports `readonly = true` in `duckdb_databases()`.
