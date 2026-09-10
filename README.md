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

CREATE SECRET ssas (TYPE xmla, MECHANISM 'ntlm', USER 'reader', PASSWORD '...');
ATTACH 'host=ssas-host port=2383 secret=ssas' AS aw (TYPE xmla);

SHOW ALL TABLES;
DESCRIBE aw."Adventure Works".DimProduct;

-- and the point of the whole thing: SSAS joined to local data
SELECT p.EnglishProductName, local.note
FROM aw."Adventure Works".DimProduct p
JOIN local_notes local ON p.ProductKey = local.k;
```

Without `ATTACH`, for metadata and ad-hoc DAX/MDX:

```sql
SELECT CUBE_NAME, CUBE_TYPE
FROM xmla_discover('host=ssas-host port=2383 secret=ssas', 'MDSCHEMA_CUBES');

SELECT * FROM xmla_execute('host=ssas-host port=2383 secret=ssas',
                           'EVALUATE TOPN(10, Sales)');
```

`MDSCHEMA_CUBES` is "show all cubes"; `MDSCHEMA_MEASURES`, `MDSCHEMA_DIMENSIONS`
and `DBSCHEMA_COLUMNS` are the describe surface. `DESCRIBE` and `SHOW ALL TABLES`
work on an attached catalog because its schemas are the instance's models and its
tables are their tables — the extension implements neither command.

The mascot is a **lesser scaup**: a diving duck, because drilling into a cube is diving, not
dabbling. The current mark is a hand-authored placeholder and looks it — replacing it with a
real illustration is a welcome first contribution. Nothing depends on the file.

## Status

| | |
|---|---|
| NTLM, end to end | **works**, verified against SQL Server 2022 on tabular and multidimensional instances |
| `ATTACH`, `SHOW ALL TABLES`, `DESCRIBE`, `SELECT` | **works** on a tabular model |
| Projection pushdown | **works** — a narrow `SELECT` sends a DAX `SELECTCOLUMNS` list, not the whole table |
| `LIMIT` | **works** by stopping the read, not by a DAX clause; DuckDB passes no limit to a scan |
| Filter pushdown | not done — DAX refuses a text literal against a numeric column, and no non-admin rowset says which columns those are (research D14) |
| `SELECT` on a multidimensional model | not supported — row scans need DAX `EVALUATE`; use `xmla_execute` with MDX |
| Kerberos | **unverified against a live server** — see below |
| Linux | supported |
| macOS | **local build only** — needs MIT krb5 (`brew install krb5`); Apple's GSS.framework cannot seal |
| Windows | not a target — you already have `msolap` |

Discovery, catalog listing and metadata retrieval complete over NTLM. `DBSCHEMA_COLUMNS`
returns 1366 rows on the test model, which is past the sealed-frame, DIME-chunking and
TCP-fragmentation thresholds all at once — the case that breaks naive implementations.

A scan streams: the protocol layer hands back a cursor, so rows are decoded as records arrive
and a query that stops asking stops the transfer. Measured on a 60398-row fact table with
three columns — `SELECT *` over the whole table 37.07 s, one column over the whole table
2.22 s, `SELECT * ... LIMIT 5` 0.27 s.

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

On **macOS** that means `brew install krb5` followed by
`PKG_CONFIG_PATH=$(brew --prefix krb5)/lib/pkgconfig`. Apple's GSS.framework is not an
option: it declares the IOV types and exports neither `gss_wrap_iov` nor `gss_unwrap_iov`,
and ships no NTLM mechanism, so it cannot seal a message at all.

A macOS build is a **local build**, not a redistributable one. Homebrew's krb5 is keg-only
and ships no static archives, so the extension links the dylibs and records their install
names verbatim — `otool -L` on the result shows
`/opt/homebrew/opt/krb5/lib/libgssapi_krb5.2.2.dylib`. The artifact therefore loads only
where that prefix is populated, which is why macOS is in `excluded_platforms` in
`description.yml` rather than published to the community registry. Linux builds have no such
constraint: krb5 is on the default library path there and the plain library name is used.

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
make test-protocol
```

Everything CI enforces, before pushing:

```bash
make check
```

`make fmt` reformats with the **same clang-format CI pins** (14, via a
container). Newer versions disagree with it, so formatting with whatever is on
your machine can produce a diff that only fails once pushed.

## Running the probe against a live instance

The spike connects, negotiates, authenticates, seals a `Discover` and prints the
rows. It is the milestone the DuckDB surface is built on, and the quickest way to
tell whether an instance is reachable and the credential works.

It must run on **Linux**: the NTLM path needs `gss-ntlmssp`, and macOS has no NTLM
GSS mechanism at all. `scripts/run-probe.sh` handles that with a container —
Apple's `container` runtime on macOS, Docker elsewhere.

```bash
export XMLA_HOST=<address of your instance>     # required
export XMLA_PORT=2383                           # pinned; there is no redirector
export XMLA_MECHANISM=ntlm                      # ntlm | kerberos | negotiate
export XMLA_USER='<principal>'                  # omit to use the ambient identity
export XMLA_PASSWORD='<password>'               # standalone NTLM only
export XMLA_CATALOG='<catalog>'                 # optional; adds TABLES/COLUMNS

./scripts/run-probe.sh
```

`XMLA_HOST` is a variable and is never stored. On a fixture it changes on every
restore, and a stale copy reads as a firewall or code fault rather than as stale
config — a mis-diagnosis that costs more than looking it up. Nothing identifying
belongs in a committed file; the leak gate enforces that, and it is right to.

Expected output ends with `PROBE OK` and a row count. Values are **scrubbed**:
`DISCOVER_DATASOURCES` returns the instance's own `MACHINE\INSTANCE` name, so it
prints as `<HOST>\TAB`.

### Notes on Apple `container`

The script deals with two traps so you do not have to, but they are worth knowing
because they bite everything else on the machine too.

**It picks the signed binary, not the one on `PATH`.** Apple's `container`
network plugin needs `com.apple.security.virtualization`, a *restricted*
entitlement macOS grants only to a signature chaining to a certificate Apple
authorised for it. A Homebrew bottle is rebuilt and **ad-hoc signed**: it declares
the entitlement and is not granted it. The symptom is not an error — containers
start, get a DHCP lease, and pass no traffic. If both installs are present,
Homebrew's usually wins `PATH`. Check with:

```bash
codesign -dvvv "$(dirname "$(dirname "$(command -v container)")")"/libexec/container/plugins/container-network-vmnet/bin/container-network-vmnet 2>&1 | grep TeamIdentifier
# TeamIdentifier=UPBK2H6LZM   <- Apple's signed .pkg, good
# TeamIdentifier=not set      <- Homebrew bottle, networking will not work
```

Install Apple's signed package from the GitHub release if you only have the
Homebrew one:

```bash
sudo installer -pkg container-<ver>-installer-signed.pkg -target /
```

**The daemon is not running after a reboot.** Every subcommand then fails with an
opaque XPC error that reads like a broken install. The script starts it; by hand
it is `container system start`.

The probe only connects **outward**, so no port is published and the container IP
never matters — which is just as well, since that IP is not routable from the
macOS host and changes across restarts.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — the layer stack, how messages get split, current status
- `specs/001-xmla-tcp-binding/` — the specification, the plan, and every decision with what
  settled it
- `test/gss/` — the mechanism experiments, runnable

## Licence

Apache-2.0.
