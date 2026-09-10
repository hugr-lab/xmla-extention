# Tasks: SSAS over the native XMLA/TCP binding

**Input**: [spec.md](./spec.md), [plan.md](./plan.md), [research.md](./research.md)

One commit per task (constitution V). `[P]` marks tasks with no dependency on each other.

## Status, 2026-09-09

The Phase 3 protocol milestone is **met**: the spike connects, negotiates, authenticates over
NTLM, seals a Discover and returns rows from a live instance — 1366 `DBSCHEMA_COLUMNS` rows,
past every splitting threshold. 73 hermetic cases pass on macOS and Linux.

Remaining: the DuckDB surface (T-034..T-037), Phase 4 and Phase 5, and the workflows still
marked below.

## Phase 1: Setup

- [x] **T-001** Extension skeleton. DuckDB pinned to **v2.0-cyanoptera** (submodule at
      a0315f71), matching `hugr-lab/mssql-extension`. Verified: `make release` builds
      `xmla.duckdb_extension` and DuckDB reports it loaded at version 0.0.1.

      Two things worth knowing. The protocol sources are compiled INTO the extension rather
      than linked as a static library, because `build_static_extension` places its target in
      DuckDB's export set and CMake then demands every linked target be exported too. And the
      extension block is guarded on `if(COMMAND build_loadable_extension)`, so a standalone
      configure — which is how the hermetic suite builds, with no DuckDB and no Kerberos —
      skips it rather than failing on an unknown command.

      **Not yet covered by CodeQL**: `src/xmla_extension.cpp` only compiles in the DuckDB
      build, and the CodeQL job builds standalone. It comes in with the extension build job,
      which is T-060's remaining scope.
- [x] **T-002** GSSAPI discovery in CMake: `krb5-gssapi` + `krb5` via pkg-config on Linux,
      `GSS.framework` on macOS. A **hard failure** when absent, not a warning — authentication
      is not optional here, so the dependency is not either.
- [ ] **T-003** [P] Test harness: a `test-cpp` target running Catch2 cases with no network.
- [ ] **T-004** [P] `.clang-format` check and the leak gate wired as CI jobs.

## Phase 2: Foundational (blocking)

- [x] **T-010** `errors`: the six categories plus `IncompleteMessage` as a subtype of
      `Protocol`. Tests assert `IncompleteMessage` is catchable as `Protocol` and that nothing
      distinguishes categories by message text. (FR-003, FR-029)
- [x] **T-011** `redact`: scrubbing anchored to real service-principal classes, not a generic
      `word/word` shape. Tests assert `text/xml`, `Envelope/Body`, `TCP/IP` and `and/or`
      survive — a generic pattern destroyed exactly the diagnostics scrubbing exists to
      preserve. (FR-030)
- [x] **T-012** `transport::Channel` seam + `BytesChannel`. Nothing above this line may touch
      a socket. (constitution III)

## Phase 3: User Story 1 — read metadata (P1) 🎯 MVP

### Protocol layer

- [x] **T-020** `dime`: encode/decode a record, four fields each padded separately to 4 bytes.
      Tests: a record whose declared bytes arrived but whose padding has not is
      `IncompleteMessage`, not decoded. (FR-001)
- [x] **T-021** `dime`: message reassembly across records by `MB`/`CF`/`ME`, returning the
      next offset so a peer packing several messages into one segment does not lose the
      remainder. (FR-005)
- [x] **T-022** `dime`: content-type negotiation and `check_negotiated`. Test that a server
      selecting binary XML or XPRESS raises `Negotiation`, not `Protocol`. (FR-007..009)
- [x] **T-023** `transport::MessageStream`: reads driven by declared lengths, buffer held
      across calls, bounded, and the bound's error says which of "never terminated" or
      "desynchronised" applies. (FR-002, FR-006)
- [x] **T-024** `SocketChannel`: connect with a deadline on every wait; the error names no
      host. (FR-025, FR-030)
- [x] **T-025** `seal_provider`: the capability probe and two implementations — `gss_wrap_iov`
      (Kerberos) and `gss_wrap` with a derived split (NTLM). The split point is
      `wrapped_len - plain_len`, never the constant 16. Receive-side uses
      `gss_wrap_iov_length` to split one wire token into the two buffers `gss_unwrap_iov`
      wants. (research D4, D5; FR-017)
- [x] **T-026** `sealing`: the 4-byte frame, ciphertext first. BOM as its own frame. Chunking.
      Refuse a padding mechanism, and refuse a frame past `uint16`. A buffer ending mid-frame,
      including a 1–3 byte partial header, is `IncompleteMessage`. (FR-016..021)
- [x] **T-027** `envelopes`: `Authenticate` in the extension namespace, `Discover` and
      `Execute` in the XMLA namespace, `BeginSession`/`Session` headers. Restriction names
      validated, values escaped. **No builder for a mutating command exists.** (FR-010, FR-011,
      FR-023, FR-028)
- [x] **T-028** `auth`: the mechanism-agnostic handshake loop, bounded rounds, every response
      fault-checked including the terminal one. (FR-012, FR-013, FR-015)
- [x] **T-029** `rowset`: parse by local element name; extract SOAP faults. (FR-022)
- [x] **T-030** `client`: negotiate → authenticate → request; capture and carry `SessionId`;
      reset all connection-scoped state on open and close the old stream first; map faults
      onto categories. (FR-023, FR-024, FR-029)

### The composition test — the one that catches the expensive bug

- [x] **T-031** A test that composes **all three splits at once**: a payload chunked into
      several sealed frames, carried in several DIME records, delivered over several short
      reads. Asserts the exact bytes come back. The reference implementation reached this
      only via a 1366-row response that happened to trigger two of the three; pinning it is
      cheaper than rediscovering it.
- [x] **T-032** `scripts/ci/check_layering.sh`: no file under `src/xmla/` may include a
      DuckDB **or GSSAPI** header. The GSSAPI half was not in the original task and was added
      because the linker found it first — `client.cpp` called `GssContext::Create` and pulled
      the protocol library into a security dependency. Verified to fail in both directions.
- [ ] **T-033** Structural test: no symbol in the extension registers an `INSERT`, `UPDATE`,
      `DELETE`, `COPY TO` or `CREATE` path. (constitution II, FR-028)

### DuckDB surface

- [x] **T-034** `xmla_secret`: a DuckDB secret type carrying mechanism, user and password, so
      no credential is passed through a connection string into a query log.
- [x] **T-035** `xmla_discover` table function over `client::discover`.
- [x] **T-036** `ATTACH ... (TYPE xmla)` → storage extension → catalog; catalogs as schemas,
      tables as tables, columns typed from `DBSCHEMA_COLUMNS`. (FR-027)
- [x] **T-037** Catalog refuses DDL/DML explicitly rather than inheriting a default that might
      translate them. (FR-028)

**Checkpoint MET.** Verified against a live SQL Server 2022 tabular instance: `ATTACH`,
`SHOW ALL TABLES`, `DESCRIBE`, `SELECT ... ORDER BY`, and a join between an SSAS table and a
local DuckDB relation. `INSERT` and `CREATE SCHEMA` are refused with the read-only message.

What D13 records about the rowsets is the part that took the measuring: only `TABLE_TYPE =
'TABLE'` is a user table, the `$` prefix is internal, `EVALUATE` qualifies its columns as
`<table>[<column>]`, and it omits the `RowNumber-<GUID>` surrogate. Each of those produced a
visibly wrong catalog before it was measured.

## Phase 4: User Story 2 — read-only query (P2)

- [ ] **T-040** `xmla_execute` table function.
- [ ] **T-041** Type mapping from the rowset's declared column types to DuckDB types, with
      anything unmapped arriving as `VARCHAR` rather than being guessed at. NOT from
      `DBSCHEMA_COLUMNS`: it reports `DBTYPE_WSTR` for every column of a tabular model, and
      `TMSCHEMA_COLUMNS` needs administrator rights. `DISCOVER_CSDL_METADATA` is the
      candidate. (research D14)
- [x] **T-042** Scan pushdown, and a row shape that suits a fact table. Delivered: a
      `RowCursor` from the protocol layer in place of a whole `Rowset`, so a scan stops
      reading when the executor stops asking (`LIMIT 5` over 60398 rows: 37.07 s → 0.27 s);
      projection pushdown as a DAX `SELECTCOLUMNS` list (1 of 3 columns: 37.07 s → 2.22 s);
      and `Rowset` re-laid-out as tagged cells rather than a `std::map` per row. Filter
      pushdown is NOT done, and research D14 records the measurement that decided it — DAX
      refuses comparing a text literal against a numeric column, and no non-admin rowset
      reveals which columns those are. Limit pushdown is not expressible: DuckDB v2.0 passes
      no limit to a table function at all. (research D14)

## Phase 5: User Story 3 — ambient identity (P3)

- [ ] **T-050** Ambient credential (ticket cache) when no user is supplied; failure to find
      one is `Authentication`, not `Connection`.
- [ ] **T-051** SPN composition: portless default, `instance=`, `use_port=`, full `spn=`
      override. (research D8)
- [ ] **T-052** The `test/kerberos/` docker-compose stack — MIT KDC plus a multi-stage client
      that builds the extension inside Linux — running the mechanism-level assertions in CI.
      SSAS is deliberately absent: it has no Linux build, and the questions this settles are
      mechanism questions.

## Phase 6: CI and polish

- [~] **T-060** `ci.yml`: lint and C++ unit tests on a linux/macos matrix are **done**, plus
      sanitizers and the leak-gate regression suite. Still outstanding: the extension build
      itself and the build-matrix resolver job that feeds it — a job output, not an `if:` on
      the build job, because GitHub does not expose the `matrix` context to `jobs.<id>.if`
      and such a test evaluates empty, silently skipping the job. Neither exists yet because
      there is no DuckDB submodule to build against; it lands with T-001.
- [x] **T-061** `kerberos.yml`: path-filtered on the auth and sealing sources, buildx layer
      caching, logs dumped on failure.
- [ ] **T-062** `mock-server.yml`: a mock instance in a container plus standalone unit tests
      on **ubuntu and macos**, to catch BSD/Linux socket divergence.
- [~] **T-063** `codeql.yml` done. ClusterFuzzLite still to add: fuzz the two byte parsers
      that consume remote input — the DIME record decoder and the sealed-frame reader — plus
      the rowset scanner, which is the third. The unit suite already runs under ASan+UBSan
      with a table of truncated and malformed inputs, which is coverage of the same code but
      not a substitute for coverage-guided fuzzing.
- [x] **T-064** `README.md` with the lesser scaup, and the `msolap` distinction in the first
      paragraph.
- [x] **T-065** `ARCHITECTURE.md`: the layer stack, how messages get split, current status —
      including what remains UNVERIFIED.

## Dependencies

- Phase 2 blocks everything.
- T-025 blocks T-026 blocks T-030.
- T-020..T-023 block T-030.
- T-031 requires T-023 and T-026; it is the checkpoint for the protocol layer.
- Phase 4 and 5 both require the Phase 3 checkpoint. They are independent of each other.

## Parallel opportunities

- T-003, T-004 with each other.
- T-010, T-011, T-012 with each other.
- T-020..T-022 (dime) with T-027, T-029 (envelopes, rowset) — different files, no shared
  headers.
- Phase 6 workflows with each other.
