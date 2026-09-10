---
title: Troubleshooting
---

## Errors carry a category

Each protocol failure maps onto a distinct DuckDB exception type, so
`error_type` is actionable without parsing message text:

| what happened | DuckDB error |
|---|---|
| never reached a server — host, port, firewall | `Connection Error` |
| reached it, could not establish identity | `Invalid Configuration Error` |
| identity established, access refused | `Permission Error` |
| the server refused the message encoding | `Not implemented Error` |
| the server understood the request and rejected it | `Invalid Input Error` |
| the bytes on the wire were not what the specification requires | `IO Error` |

Every message is scrubbed of identifying tokens before it arrives.

## It hangs instead of failing

Almost always the **port**. There is no named-instance redirector, so a wrong
port has nothing to answer it and the connect waits out its timeout. Pin the
port in `msmdsrv.ini` and pass it explicitly. `timeout` bounds the wait; it
defaults to 30 seconds and there is no unbounded mode.

## "could not connect on port 2383"

In order of how often it is each one:

1. **The address is stale.** If the instance is a VM that gets a new address on
   restore, check the current one before suspecting the firewall or the code. A
   stale address reads as a firewall or code fault, and that mis-diagnosis is
   expensive.
2. **Your egress changed.** Compare your current outbound address against the
   firewall's source ranges. Home and office addresses drift.
3. **The instance is not running.** SSAS named instances are separate services.

## An empty result

An empty rowset is a **meaningful** answer — "no rows visible to this account" —
so the extension works hard to make sure nothing else can look like one:

- A response that does not decrypt to XML is refused, not returned as zero rows.
- A response with no plaintext at all is refused.
- A multidimensional **cellset** is refused rather than reported as an empty
  rowset. That one was a real defect: before the client sent `Format=Tabular`,
  every MDX query returned zero rows and no error.

So if you get an empty result, the account most likely cannot see the object.
Check its permissions on the server.

## A column of all NULLs

Historically this meant the scan looked a result column up under the wrong name.
`EVALUATE 'DimProduct'` returns `DimProduct[ProductKey]`, an aliased projection
returns `[ProductKey]`, and a DISCOVER rowset returns `ProductKey` — the mapping
now accepts all three, and a hermetic test pins each. If you see it anyway, it is
worth an issue.

## "is in a multidimensional model"

Expected. Use MDX through `xmla_execute`; see [Cubes and MDX](../cubes.md).

## NTLM fails with "unknown mechanism"

`gss-ntlmssp` is not installed. It is a separate package from the Kerberos
libraries.

## macOS cannot seal a message

Apple's `GSS.framework` declares the IOV types and exports neither
`gss_wrap_iov` nor `gss_unwrap_iov`, and ships no NTLM mechanism. Install MIT
krb5 and point `pkg-config` at it:

```bash
brew install krb5
PKG_CONFIG_PATH=$(brew --prefix krb5)/lib/pkgconfig cmake -S . -B build
```

## Something needs a live instance to reproduce

`scripts/run-sql-tests.sh` builds the extension and runs the whole SQL surface in
a Linux container, and with `XMLA_HOST` set it also attaches a live instance. See
[Development](../development.md).
