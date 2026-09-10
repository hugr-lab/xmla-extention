---
title: Development
---

## Building

```bash
git submodule update --init --recursive
make
```

The only native dependency is **MIT krb5** (`libkrb5-dev` on Debian/Ubuntu,
`krb5-devel` on RHEL/Fedora, `krb5` on Homebrew), plus **`gss-ntlmssp`** if you
need NTLM. Sealing is done by the security context rather than by TLS, so there
is no TLS library involved and none may be added for that purpose.

On macOS that means `brew install krb5` and
`PKG_CONFIG_PATH=$(brew --prefix krb5)/lib/pkgconfig`; the result is a
[local build only](./reference/limitations.md#macos-builds-are-not-redistributable).

## Tests

The hermetic protocol suite needs no security library and no server, and runs on
a machine that has never contacted an Analysis Services instance:

```bash
make test-protocol
```

Everything CI enforces, before pushing — offline and dependency-free by design,
so it works on a plane:

```bash
make check
```

`make fmt` reformats with the **same clang-format version CI pins** (14, via a
container). Newer versions disagree with it, so formatting with whatever is on
your machine can produce a diff that only fails once pushed.

## The SQL surface needs Linux

`make check` covers everything that needs no server and no security library. The
rest has to run on Linux: the NTLM path needs `gss-ntlmssp`, which macOS does not
ship, and a macOS build links keg-only Homebrew krb5 and is not the artifact
anyone ships.

```bash
./scripts/run-sql-tests.sh
```

That builds the extension and runs the hermetic suite, every `test/sql/*.test`
and the C API checks inside a container — Apple's `container` runtime on macOS,
Docker elsewhere. The repository is bind-mounted rather than copied and the build
tree persists, so the first run is a full DuckDB build and every run after it is
incremental.

Set `XMLA_HOST` and it also attaches a live instance and asserts what it finds.
Add `XMLA_TABLE` and it runs the scan checks that nothing server-free can
reach — the projection pushdown, `count(*)`, the early-abandoned `LIMIT`, and the
DDL refusal:

```bash
export XMLA_HOST=<address of your instance>
export XMLA_USER='<principal>' XMLA_PASSWORD='<password>'
export XMLA_CATALOG='<model>'
export XMLA_TABLE='"<model>"."<table>"'

./scripts/run-sql-tests.sh
```

The password is written to a `0600` file the runtime reads, never to the command
line: `-e KEY=VALUE` puts the value in the runtime's `ARGV`, and
`/proc/<pid>/cmdline` is world-readable.

## The probe

`scripts/run-probe.sh` connects, negotiates, authenticates, seals a `Discover`
and prints the rows. It is the milestone the DuckDB surface is built on, and the
quickest way to tell whether an instance is reachable and a credential works.

## What CI runs

Nine checks: lint, C++ unit tests on Linux and macOS, ASan+UBSan over the
protocol suite (which is fed truncated and malformed input on purpose, so it is
nearly free coverage of exactly the code that most needs it), CodeQL, the SQL
surface plus the C API checks, and two mechanism-level jobs — NTLM's missing IOV
entry points, and the `gss_wrap_iov` layout against a real MIT KDC.

## Nothing identifying gets committed

Hostnames, addresses, account names, realms, SPNs, machine names and security
identifiers are forbidden in every tracked file, and a hook enforces it on every
commit — including refusing binaries it cannot read, rather than reporting clean
on a file it never scanned. That gate has blocked this repository's own authors
more than once, which is the point.

Handshake fixtures are **synthesized, never captured**, for the same reason: a
real GSS token carries the principal, the realm and often the machine name, and
no scrubber can reliably redact arbitrary token structure.

## Provenance

The sealed-frame layout is not in `[MS-SSAS]`; it was established by studying how
Microsoft's own client frames these messages. This repository contains
**findings only** — statements about the wire format, and no third-party source
of any kind. That boundary is what keeps the project distributable, and it is a
standing rule rather than a one-off: see the Provenance Boundary in
`.specify/memory/constitution.md`.

## Where the decisions live

`specs/001-xmla-tcp-binding/` holds the specification, the plan, and every
decision with the evidence that settled it. `ARCHITECTURE.md` is the layer-level
tour. `test/gss/` holds the mechanism experiments, runnable.
