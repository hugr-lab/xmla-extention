<p align="center">
  <img src="docs/assets/lesser-scaup.svg" alt="A lesser scaup, diving" width="200"/>
</p>

<h1 align="center">xmla</h1>

<p align="center">
  <em>Query SQL Server Analysis Services from DuckDB, on Linux.<br/>
  No IIS. No msmdpump. No COM. No Windows components anywhere in the path.</em>
</p>

---

DuckDB's existing `msolap` extension reaches Analysis Services only on Windows, because it
binds COM and OLE DB through the MSOLAP provider. The alternative — the `xmla` Python package
and friends — speaks XMLA only over HTTP, which is what forces an IIS deployment in front of
every instance in the first place.

This extension speaks the **native XMLA/TCP binding** directly. It is named for the wire
protocol rather than for a product, because the same protocol serves SSAS, Azure Analysis
Services and Power BI Premium endpoints — and because naming it after a provider DLL would
misdescribe an implementation that uses no provider at all.

```sql
INSTALL xmla FROM community;
LOAD xmla;

ATTACH 'host=ssas-host port=2383' AS aw (TYPE xmla);

SHOW ALL TABLES;
SELECT * FROM aw.model."Internet Sales" LIMIT 10;
```

The mascot is a **lesser scaup**: a diving duck, because drilling into a cube is diving, not
dabbling. The current mark is a hand-authored placeholder and looks it — replacing it with a
real illustration is a welcome first contribution. Nothing depends on the file.

## Status

| | |
|---|---|
| NTLM, end to end | **works**, verified against SQL Server 2022 on tabular and multidimensional instances |
| Kerberos | **unverified against a live server** — see below |
| Linux | supported |
| macOS | needs MIT krb5 (`brew install krb5`); Apple's GSS.framework cannot seal |
| Windows | not a target — you already have `msolap` |

Discovery, catalog listing and metadata retrieval complete over NTLM. `DBSCHEMA_COLUMNS`
returns 1366 rows on the test model, which is past the sealed-frame, DIME-chunking and
TCP-fragmentation thresholds all at once — the case that breaks naive implementations.

**Kerberos is expected to work.** The mechanism-level questions are settled against a real MIT
KDC in CI: `gss_wrap_iov` produces the frame's layout, pads for none of the four AES session-key
enctypes, and token size varies (60/64/72 bytes) so nothing hardcodes it. What is *not* settled
is whether a Kerberos-speaking SSAS lays out its single token buffer the way we assemble ours.
That needs a domain-joined instance, and the available test fixture is a standalone workgroup
machine whose SSAS can only speak NTLM. It is marked UNVERIFIED rather than claimed — see
[ARCHITECTURE.md](ARCHITECTURE.md) and `specs/001-xmla-tcp-binding/research.md`.

## Requirements

- **A pinned port.** There is no named-instance redirector: the service on TCP 2382 has no
  public specification and does not speak the [MC-SQLR] framing that resolves database-engine
  instances. Pin the port in `msmdsrv.ini`. A firewall rule is needed either way.
- **MIT krb5** (`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on RHEL/Fedora, `krb5` on
  Homebrew). It is the only native dependency — sealing is done by the security context, so
  there is no TLS library involved.
- **`gss-ntlmssp`** if you need NTLM.

## Credentials

Never in the connection string, so nothing lands in a query log:

```sql
CREATE SECRET ssas (TYPE xmla, MECHANISM 'ntlm', USER '...', PASSWORD '...');
```

With a Kerberos ticket in the cache, supply nothing at all and the ambient identity is used.

## Read-only

Two different guarantees, and the difference matters:

- **Metadata is read-only by construction.** No envelope builder for a mutating command
  exists, so no argument to any discovery function can reach one. A test asserts the absence
  structurally.
- **Statements are read-only by validation.** `xmla_execute` refuses anything whose first
  significant keyword is not `SELECT`, `EVALUATE`, `WITH`, `DEFINE` or `VAR`. This is needed
  because XMLA's `<Statement>` element carries the *whole* command surface — MDX writeback
  (`UPDATE CUBE`), DMX (`INSERT INTO`, `DROP MINING MODEL`) and stored-procedure `CALL` all
  travel through it, so removing a `Create`/`Alter` builder closes one route and not the
  others.

The second is a guard, not a proof. **Grant the connecting account read-only permissions on
the server.** That is the only control that cannot be reasoned around, and no client-side
check substitutes for it.

## Nothing identifying gets committed

Hostnames, addresses, account names, realms, SPNs, machine names and security identifiers are
forbidden in every tracked file, and a hook enforces it on every commit — including refusing
binaries it cannot read, rather than reporting clean on a file it never scanned.

That gate has blocked this repository's own authors more than once, which is the point.

## Building

```bash
git submodule update --init --recursive
make
```

The hermetic protocol tests need no security library and no server:

```bash
cmake -S . -B build/test -DXMLA_REQUIRE_GSS=OFF && cmake --build build/test
./build/test/xmla_test
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — the layer stack, how messages get split, current status
- `specs/001-xmla-tcp-binding/` — the specification, the plan, and every decision with what
  settled it
- `test/gss/` — the mechanism experiments, runnable

## Licence

Apache-2.0.
