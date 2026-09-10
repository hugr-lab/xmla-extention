---
title: Authentication
---

`[MS-SSAS]` carries GSS-API security tokens **inside SOAP**: `Authenticate` out,
`AuthenticateResponse` back, repeating until the mechanism reports completion.
One loop serves Kerberos and NTLM because the specification's exchange is
mechanism-agnostic.

Two details a working implementation cannot skip:

- `Authenticate` uses a **different namespace** from `Discover` and `Execute` —
  `http://schemas.microsoft.com/analysisservices/2003/ext`, not the XMLA
  namespace. A live server rejects the wrong one outright.
- Every authenticate response is fault-checked, **including the terminal one**.
  For NTLM the client context completes as it emits its last token, so a
  handshake that returns without inspecting that reply silently drops a
  "Logon failure" and reports success.

The credential carries **no password field**. Where NTLM needs one on a
standalone server it is passed to the security layer directly and never
retained.

## NTLM

Verified end to end against SQL Server 2022 Analysis Services, on both a tabular
and a multidimensional named instance. `DBSCHEMA_COLUMNS` returns 1366 rows on
the test model, which is past the sealed-frame, DIME-chunking and
TCP-fragmentation thresholds all at once — the case that breaks naive
implementations.

NTLM needs `gss-ntlmssp` installed. It exports no IOV entry points, which is why
sealing uses the [wrap-and-split provider](./sealing.md#two-seal-providers-chosen-by-capability)
there.

## Kerberos

**Expected to work, and unverified against a live server.** What is settled and
what is not:

*Settled* against a real MIT KDC in CI — the IOV layout, the absence of padding
across four AES enctypes, the variable token size, and that `GSS_C_DCE_STYLE` is
not the switch to SSPI's single-buffer form. See
[Sealing](./sealing.md#what-was-settled-against-a-real-kdc).

*Not settled*: whether a Kerberos-speaking SSAS concatenates HEADER and TRAILER
in its single token buffer the way this client does, or rotates them
(RFC 4121 RRC). That needs a domain-joined instance; the available fixture is a
standalone workgroup machine whose SSAS can only do NTLM.

Also unsettled is **which SPN form** a production instance registers — the
portless form GSSAPI builds, or the port-suffixed form ADOMD's `DsMakeSpn`
produces. NTLM ignores the target entirely, which is why the portless form has
worked so far and proves nothing about Kerberos. Both are reachable through
[options](../reference/options.md).

## Nothing identifying is committed

Hostnames, addresses, account names, realms, SPNs, machine names and security
identifiers are forbidden in every tracked file of this repository, and a hook
enforces it on every commit — including refusing binaries it cannot read, rather
than reporting clean on a file it never scanned. That gate has blocked the
project's own authors more than once, which is the point.

Error messages are scrubbed on the way out for the same reason:
`DISCOVER_DATASOURCES` returns the instance's own `MACHINE\INSTANCE` name, and it
surfaces as `<HOST>\TAB`.
