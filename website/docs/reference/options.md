---
title: Connection options
---

Space-separated `key=value` pairs. Keys are case-insensitive. **An unknown key is
an error**, not a warning: a silently dropped `mechanism=ntlm` authenticates with
something the caller did not ask for.

| key | default | meaning |
|---|---|---|
| `host` | — | required, from here or from a secret |
| `port` | — | **required and pinned.** No default; see below |
| `mechanism` | `kerberos` | `kerberos`, `negotiate` or `ntlm` |
| `user` | ambient | principal; unset means the process's own credentials |
| `catalog` | all | which model to present, or query against |
| `secret` | — | name of an `xmla` secret to draw fields from |
| `spn` | derived | full SPN override, `<service>/<host>` |
| `instance` | — | named instance, for SPN composition |
| `use_port` | `false` | append `:<port>` to the SPN, as `DsMakeSpn` does |
| `timeout` | `30` | seconds; positive and at most `86400` |

`password` is **rejected** in a connection string. That string reaches the query
log and the query plan; use a secret.

## Why the port has no default

A default would invite guessing between a default instance's well-known port and
a named instance's pinned one, and guessing wrong presents as a **hang** rather
than an error. There is also no named-instance redirector to ask: the service on
TCP 2382 has no public specification and was verified empirically not to speak
the `[MC-SQLR]` framing that resolves database-engine instances on UDP 1434. The
neighbouring `mssql` extension does implement MC-SQLR — a different, documented
protocol whose resolver does not transfer.

Pin the port in `msmdsrv.ini`. A firewall rule is needed either way, so pinning
costs the operator nothing.

## Booleans and numbers are validated

An unrecognised boolean is an error rather than a silent `false`, because
`use_port` selects between two different SPNs and `use_port=flase` quietly
meaning false presents as a Kerberos failure with no hint at the cause.

`port` goes through a real parse rather than a cast: `port=65538` is refused
rather than silently truncated to 2. `timeout` has an upper bound as well as a
lower one, so `timeout=inf` is refused rather than reaching a cast where it is
undefined behaviour.

## Resolution order

1. The secret's fields, for anything the connection string did not set.
2. Defaults.
3. Validation.

That order is fixed in one place and not left to callers, because getting it
wrong is silent: applying defaults **before** the secret makes the default beat
the secret, so a secret carrying `mechanism='ntlm'` is ignored and every
connection attempts Kerberos. That happened twice, in two places, before the
steps were collapsed into a single entry point.
