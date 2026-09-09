# Implementation Plan: SSAS over the native XMLA/TCP binding

**Branch**: `001-xmla-tcp-binding` | **Date**: 2026-09-09 | **Spec**: [spec.md](./spec.md)

## Summary

A DuckDB extension, `xmla`, that reaches Analysis Services over the native TCP binding from
Linux. Four protocol layers in plain C++ with no DuckDB dependency — DIME framing, message
reassembly, the SOAP-carried GSS handshake, and the sealed frame — with the DuckDB catalog
and table-function surface layered strictly above them. The protocol layer's only native
dependency is GSSAPI/krb5; sealing is done by the security context, so no TLS library is
involved.

## Technical Context

**Language/Version**: C++11, matching what DuckDB's build system imposes. `CMAKE_CXX_STANDARD`
is not set by this project — setting it with `CACHE FORCE` overrides DuckDB's own settings and
causes ODR issues, which is a mistake the neighbouring extension documents having made.

**Primary dependencies**: DuckDB (submodule), `extension-ci-tools` (submodule), and MIT krb5
(`libgssapi_krb5` + `libkrb5`) on every platform — including macOS (research D11). Nothing
else.
`vcpkg.json` exists but declares no packages, because there are none to declare.

**Storage**: none. The extension holds no state across sessions.

**Testing**: Catch2 through DuckDB's `unittest` binary for the protocol layer, driven entirely
through the byte seam with sockets disabled; sqllogictest for the DuckDB surface; the
container probes in `test/gss/` for mechanism questions.

**Target platform**: Linux x86-64 first. macOS builds and runs the *hermetic protocol tests*
in CI, to catch BSD/Linux socket divergence in `transport` — but a working macOS client needs
MIT krb5 from Homebrew, because Apple's `GSS.framework` exports no `gss_wrap_iov` and no NTLM
mechanism and so cannot seal a message at all (research D11). Windows is not a target — a
Windows user already has `msolap`, and reproducing a COM dependency would forfeit the point.

**Performance goals**: none stated. Metadata discovery and analytic queries are latency-bound
on the server. The one performance property that matters is that reassembly must not be
quadratic in the number of reads for a large rowset, which the reference implementation is
and this one should not be.

**Constraints**: read-only by construction; no unbounded waits; no identifying token in any
committed file or emitted string; no Windows or .NET component on any platform.

**Scale/Scope**: a metadata surface and read-only statement execution. `DBSCHEMA_COLUMNS` on a
modest model returned 1366 rows in the reference implementation, which is the largest response
shape actually observed and already past every splitting threshold.

## Constitution Check

| Principle | How this plan satisfies it | Where it could fail |
|---|---|---|
| I. No Secret Leakage | The leak gate is already committed and runs on every commit. Errors are built from categories and scrubbed detail, never from raw server text. Fixtures for the handshake are synthesized. | A test that pastes a real capture. Guarded by the gate scanning every tracked file including binaries, which refuses what it cannot read. |
| II. Read-Only by Construction | No `INSERT`/`UPDATE`/`DELETE`/`COPY`/`CREATE` path is registered; the catalog refuses DDL rather than translating it. There is no envelope builder for a mutating command, so no argument can reach one. | A DuckDB catalog API that mutates by default if not overridden. Task T-032 asserts the absence structurally rather than trusting the override. |
| III. Offline-First Hermetic Tests | The protocol layer takes a `Channel` interface and carries no DuckDB include. The default suite runs with no server. | A protocol source acquiring a DuckDB include for convenience. Task T-031 makes that a build failure, not a review note. |
| IV. Spec-Governed Protocol Work | Every layer cites [MS-SSAS] at the point of implementation; the sealed frame, which the specification does not document, cites the experiments in `test/gss/` and the named ADOMD types. Open questions are marked UNVERIFIED in `research.md` D5 and D8. | Stating the Kerberos token layout as settled. It is not, and the code must not depend on which of the two forms SSAS emits. |
| V. Spec-Driven with Review Gates | Tasks are one commit each, in dependency order. | Batching tasks to move faster. |

**Result**: PASS. No deviation to record in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```
specs/001-xmla-tcp-binding/
├── spec.md              # what and why
├── plan.md              # this file
├── research.md          # decisions, each with what settled it
├── data-model.md        # the entities and their invariants
├── quickstart.md        # attach and query, end to end
├── contracts/
│   └── public-api.md    # the DuckDB-visible surface
└── checklists/
    └── requirements.md  # spec quality gate
```

### Source Code (repository root)

The layout follows `hugr-lab/mssql-extension`, which is the closest existing neighbour: a
DuckDB extension speaking a hand-rolled wire protocol with catalog integration. What carries
over is the top-level build shape and, more importantly, the seam — that extension keeps
`src/tds/*` free of DuckDB includes so it can be unit-tested without a database. That is the
same seam constitution III requires here.

What does not carry over is roughly a third of its tree: read-only means no `dml/`, no
`copy/`, no `ctas/`. And there is no OpenSSL and no simdutf, because sealing is the security
context's job and there is no UTF-16 bulk path.

```
CMakeLists.txt              # extension targets; discovers GSSAPI per platform
extension_config.cmake      # registers the extension with DuckDB's build
Makefile                    # includes extension-ci-tools/makefiles/duckdb_extension.Makefile
vcpkg.json                  # declares no packages; present for the CI tooling's benefit
description.yml             # community-extension metadata
duckdb/                     # submodule
extension-ci-tools/         # submodule

src/
├── xmla_extension.cpp      # entry point, registration
├── xmla_storage.cpp        # ATTACH -> catalog
├── xmla_secret.cpp         # DuckDB secret for credentials
├── include/                # headers mirroring the tree below
├── xmla/                   # THE PROTOCOL LAYER. No DuckDB include may appear here.
│   ├── dime.cpp            # record framing, content-type negotiation
│   ├── transport.cpp       # Channel, SocketChannel, message reassembly
│   ├── sealing.cpp         # the 4-byte frame; chunking; unsealing
│   ├── seal_provider.cpp   # gss_wrap split vs gss_wrap_iov, chosen by capability
│   ├── auth.cpp            # the GSS handshake carried in SOAP
│   ├── envelopes.cpp       # SOAP construction (no mutating builder exists)
│   ├── rowset.cpp          # response parsing, fault extraction
│   ├── redact.cpp          # scrubbing
│   └── errors.cpp          # the failure categories
├── catalog/                # DuckDB catalog entries over Discover results
└── functions/              # table functions: xmla_discover, xmla_execute

test/
├── cpp/                    # hermetic protocol tests, sockets disabled
├── sql/                    # sqllogictest against the DuckDB surface
├── gss/                    # the mechanism probes (see its README)
└── kerberos/               # docker-compose KDC stack for CI
```

**Structure decision**: single project, protocol layer isolated by directory and enforced by a
build-time check rather than by convention. The isolation is not stylistic — it is what makes
constitution III's "passes on a machine that has never contacted an instance" achievable, and
a single stray include would quietly end it.

## Layering

Strictly bottom-up; no lower layer includes a higher one.

```
   catalog / functions      DuckDB surface: ATTACH, table functions, type mapping
        |
      client                session lifecycle, request/response, error categories
        |
       auth                 GSS handshake carried inside SOAP
        |
     transport              socket lifecycle, timeouts, message reassembly
        |
       dime                 DIME record framing and content-type negotiation
        |
      socket
```

`sealing`, `envelopes`, `rowset`, `redact` and `errors` are leaves used across layers. Sealing
is deliberately *not* in the stack: the handshake is sent unsealed, and sealing is applied by
the client to every message after it, on the way into the transport. Placing it between `auth`
and `transport` reads as though the handshake passed through it, which it does not.

## How messages get split

Three independent splits apply to one message, each handled at a different layer, and they
compose. Getting this wrong corrupts large rowsets specifically, which is the case least
likely to be exercised by a first test.

1. **Sealed-frame chunking** (`sealing`) — a payload longer than the chunk size becomes
   several frames, each with its own header, ciphertext and token.
2. **DIME record chunking** (`dime`) — a message too large for one record is split across
   several, `CF` set on all but the last, `MB` on the first, `ME` on the last. Per [MS-SSAS] a
   chunked sequence is contained within one message and never spans messages, so the boundary
   is unambiguous.
3. **TCP fragmentation** (`transport`) — reads driven by declared lengths, buffer held across
   calls.

A test pins the composition of all three rather than relying on a rowset that happened to
trigger two of them.

## Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| Kerberos token layout (research D5) | If SSAS rotates its single token buffer and we concatenate, Kerberos fails at the first sealed message with no server-side diagnostic. | Both forms are cheap to produce. The provider interface can carry a second Kerberos implementation without disturbing anything above it. Not coded speculatively; recorded as the known open question. |
| GSSAPI availability at build time | An absent krb5 turns a build failure into a silent capability loss. | Discovery is explicit in CMake with a hard failure, not a warning. The neighbour makes it optional; here authentication is not optional, so neither is the dependency. |
| Quadratic reassembly | A large rowset arrives over many reads; re-walking every record per read is O(n²). | A completeness pre-check before decoding, rather than decode-and-catch. |
| `msolap` name confusion | Users searching for SSAS support find the Windows-only extension first. | The README states the difference in its first paragraph. |
