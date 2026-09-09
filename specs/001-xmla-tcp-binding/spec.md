# Feature Specification: SSAS over the native XMLA/TCP binding, as a DuckDB extension

**Feature Branch**: `001-xmla-tcp-binding`

**Created**: 2026-09-09

**Status**: Draft

**Input**: A DuckDB extension in C++ that reads SQL Server Analysis Services over the native
XMLA/TCP binding on Linux, with no IIS/msmdpump, no COM, and no Windows components.

## Why this exists

SSAS speaks XMLA over two bindings: HTTP through the `msmdpump` ISAPI extension hosted in
IIS, and a native TCP binding. DuckDB's existing `msolap` extension reaches only the second
of those and only on Windows, because it binds COM/OLE DB through the MSOLAP provider. A
Linux consumer that wants SSAS metadata or query results today must stand up IIS in front of
every instance.

This extension removes that requirement. It is named for the wire protocol rather than a
product because the same protocol serves SSAS, Azure Analysis Services and Power BI Premium
endpoints, and because naming it after a provider DLL would misdescribe an implementation
that uses no provider at all.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Read a cube's metadata from Linux (Priority: P1)

An analyst on Linux has a DuckDB session and the network address of an Analysis Services
instance. They install the extension, attach the instance, and list the catalogs and their
tables and columns — without anyone installing IIS, without a Windows host, and without a
Microsoft provider on their machine.

**Why this priority**: It is the whole gap. Metadata discovery is also the smallest thing
that requires every hard part to work — the DIME framing, the GSS handshake, the sealed
frame, and rowset parsing — so nothing below it can be faked.

**Independent Test**: Attach an instance and run a metadata query; the rows returned match
what the same `DISCOVER`/`DBSCHEMA` request returns over the HTTP binding from the same
account. Fully testable against recorded bytes with no server present.

**Acceptance Scenarios**:

1. **Given** a reachable instance and an account with read access, **When** the user runs
   `ATTACH 'host=<host> port=<port>' AS aw (TYPE xmla)`, **Then** the attach succeeds and
   the catalog is queryable.
2. **Given** an attached instance, **When** the user queries the catalog's table list,
   **Then** every catalog the account may see is listed, and a catalog the account may not
   see is absent rather than an error.
3. **Given** an account with no access to any catalog, **When** the user lists catalogs,
   **Then** an empty result is returned — distinct from a refusal, which raises.
4. **Given** an unreachable host, **When** the user attaches, **Then** the error names the
   failure category and contains no hostname, address or account name.

---

### User Story 2 - Run a read-only analytic query (Priority: P2)

The analyst issues a DAX or MDX statement against an attached catalog and receives its
result as a DuckDB relation they can join against local data.

**Why this priority**: It is the reason to attach rather than to export, but it is strictly
downstream of User Story 1 — the same envelope, framing and sealing carry it, so it adds
surface rather than risk.

**Independent Test**: Execute a statement against recorded response bytes and assert the
resulting relation's columns and values.

**Acceptance Scenarios**:

1. **Given** an attached catalog, **When** the user executes a read-only statement, **Then**
   the rowset is returned as a relation with one column per rowset column.
2. **Given** a statement the server rejects, **When** it is executed, **Then** the server's
   own explanation is surfaced, scrubbed of identifying tokens.

---

### User Story 3 - Authenticate as the ambient identity (Priority: P3)

On a domain-joined Linux host with a Kerberos ticket, the analyst attaches without supplying
a credential at all; the extension uses the ticket cache.

**Why this priority**: It is what a production deployment will actually use, but NTLM with an
explicit credential is what can be verified end to end today (see Assumptions), so Kerberos
follows rather than leads.

**Independent Test**: The handshake loop is mechanism-agnostic and is tested against
synthesized tokens for both mechanisms; a live Kerberos session is settled in CI against an
MIT KDC rather than against SSAS.

**Acceptance Scenarios**:

1. **Given** a valid ticket in the cache, **When** the user attaches with no credential,
   **Then** the ambient identity is used.
2. **Given** no ticket and no credential, **When** the user attaches, **Then** the failure is
   reported as an authentication failure, not a connection failure.

---

### Edge Cases

- A response larger than one sealed frame, one DIME record, or one socket read — and all
  three at once. These are three independent splits at three layers and they compose; a
  rowset of ~1300 rows was observed to trigger at least two of them simultaneously.
- A message that ends mid-frame, including a 1–3 byte partial frame header. This is
  "read more", never "truncated plaintext", and never silently short data.
- A peer that packs several messages into one TCP segment. The reader must consume exactly
  one message and keep the remainder.
- A DIME record whose declared bytes have arrived but whose 4-byte padding has not. This is
  incomplete, not decoded; treating it as decoded desynchronises the stream and surfaces as
  a bogus version error one message later.
- A server that selects binary XML or XPRESS compression. This is a scope change to report
  loudly, not a fallback to absorb.
- A reconnect on an already-used session. Connection-scoped state — the negotiation bit and
  the session id — must be reset, because a stale session id or a negotiation bit set on the
  first record is silently fatal.
- A security mechanism that pads the plaintext. The frame has no field for the unpadded
  length, so this must be refused with a message naming the limitation rather than sending a
  body the server fails to parse for reasons it cannot report.
- A named instance with no pinned port. There is no usable redirector, so this must fail with
  an actionable message rather than hang.

## Requirements *(mandatory)*

### Functional Requirements

**Transport and framing**

- **FR-001**: The extension MUST compose messages using DIME records as [MS-SSAS] requires
  for the TCP transport, honouring the separate 4-byte padding of each of the OPTIONS, ID,
  TYPE and DATA fields.
- **FR-002**: The reader MUST be driven by the header's declared lengths, never by the peer
  going quiet, and MUST hold a buffer across reads.
- **FR-003**: "Needs more bytes" and "malformed" MUST be distinct error types. No code path
  may distinguish them by inspecting message text.
- **FR-004**: A message that ends mid-frame MUST be an error, never silently truncated
  plaintext.
- **FR-005**: The reader MUST consume exactly one message per call and retain any remainder.
- **FR-006**: The unparsed read buffer MUST be bounded, and exceeding the bound MUST report
  which of "the peer never terminated the message" or "the stream is desynchronised" applies.

**Negotiation**

- **FR-007**: The extension MUST negotiate clear-text `text/xml` and MUST NOT request binary
  XML or XPRESS compression.
- **FR-008**: The extension MUST NOT set the response-compression bit. A server that is asked
  for compression returns compressed XML that arrives as convincing binary noise rather than
  as an error.
- **FR-009**: A server that selects binary XML or compression anyway MUST raise a distinct
  negotiation failure, not a parse failure and not a silent fallback.

**Authentication**

- **FR-010**: Security tokens MUST be carried inside SOAP `Authenticate` /
  `AuthenticateResponse` messages, repeating until the mechanism reports completion or error.
- **FR-011**: The `Authenticate` envelope MUST use the Analysis Services extension namespace,
  not the XMLA namespace. A live server rejects the wrong one outright.
- **FR-012**: Every authenticate response MUST be fault-checked, including the terminal one.
  For NTLM the client context completes as it emits its last token, so a handshake that
  returns without inspecting that reply silently drops a logon failure and reports success.
- **FR-013**: One handshake loop MUST serve Kerberos and NTLM; the exchange is
  mechanism-agnostic and MUST NOT branch on the mechanism name.
- **FR-014**: The extension MUST NOT retain a password. Where one is needed it MUST pass
  directly to the security layer.
- **FR-015**: A handshake that does not converge within a bounded number of rounds MUST fail
  rather than loop.

**Sealing**

- **FR-016**: Every message after the handshake MUST be sealed with the negotiated security
  context and framed as `uint16 dataSize | uint16 tokenSize | ciphertext | token`, all
  little-endian, **ciphertext first and token second**.
- **FR-017**: Neither size field may be hardcoded. `tokenSize` MUST be written from the
  actual token length and read from the declared header value.
- **FR-018**: The UTF-8 BOM MUST be sealed as its own frame before the body.
- **FR-019**: A payload longer than the chunk size MUST become several sealed frames, each
  with its own header, ciphertext and token; the reader MUST walk them by their declared
  sizes and concatenate the plaintext.
- **FR-020**: A frame whose ciphertext or token exceeds the `uint16` size fields MUST be
  refused rather than truncated.
- **FR-021**: A mechanism that reports non-zero padding MUST be refused with a message naming
  the missing unpadded-length field.
- **FR-022**: An unsealed response that does not decrypt to an XML document MUST raise,
  rather than parse to an empty rowset. An empty rowset is a meaningful answer and must not
  be indistinguishable from a cipher-layer failure.

**Session**

- **FR-023**: The extension MUST capture the `SessionId` the server returns to `BeginSession`
  and carry it on every later request.
- **FR-024**: Connection-scoped state MUST be reset on reconnect: the negotiation bit is
  clear on the first record and set on every later one, and a stale session id or a
  negotiation bit set on the first record is silently fatal.
- **FR-025**: Every network operation MUST be bounded by a timeout, and there MUST be no
  option to disable it.

**Addressing**

- **FR-026**: An instance MUST be addressed by host and a pinned port. The extension MUST NOT
  attempt the named-instance redirector on TCP 2382, which has no public specification and
  does not speak the [MC-SQLR] framing that resolves database-engine instances.

**DuckDB surface**

- **FR-027**: `ATTACH ... (TYPE xmla)` MUST present the instance as a queryable catalog whose
  schemas and tables correspond to the instance's catalogs and their tables.
- **FR-028**: The extension MUST expose no operation that creates, alters, refreshes or
  deletes a server-side object. The attached catalog MUST refuse DDL and DML rather than
  translating them, and no `COPY TO`, `INSERT`, `UPDATE`, `DELETE` or `CREATE` path may be
  registered.
- **FR-028a**: The `Execute` path MUST validate the statement against an **allowlist** of
  query keywords and refuse anything else. This is a different and weaker guarantee than
  FR-028, and the difference is load-bearing: the XMLA `<Statement>` element is the entry
  point to the entire command surface, so MDX writeback (`UPDATE CUBE`), DMX (`INSERT INTO`,
  `DELETE FROM`, `DROP MINING MODEL`) and stored-procedure `CALL` all reach the server
  through it. Absence of a `Create`/`Alter` envelope builder removes one route to mutation
  and not the others.
- **FR-028b**: The statement guard MUST be an allowlist rather than a denylist. The set of
  ways to mutate through `<Statement>` is open-ended and server-version-dependent; the set of
  ways to ask a question is small and stable. A denylist would have to be complete to be
  worth anything.
- **FR-028c**: The guard MUST NOT be presented as sufficient. Granting the connecting account
  read-only permissions on the server is the only control that cannot be reasoned around, and
  the documentation MUST say so rather than implying the client alone makes mutation
  impossible.
- **FR-029**: Failures MUST be reported in categories a caller can act on without parsing
  message text: connection, authentication, authorization, negotiation, server, protocol.
- **FR-030**: No error message, log line or exception may contain a hostname, address,
  account name, realm, SPN, machine name or security identifier.

### Key Entities

- **Connection target**: a host and a pinned port, plus a timeout. No default port, because a
  default invites guessing between a default instance's well-known port and a named
  instance's pinned one, and guessing wrong presents as a hang.
- **Credential**: what the security layer authenticates with — a mechanism, an optional
  principal, and how the SPN is to be composed. It carries no password.
- **Negotiated terms**: the content type and the binary/compression flags, settled once per
  session and immutable thereafter.
- **Session**: an authenticated conversation with an instance, holding the sealed-message
  context and the server's session id.
- **Rowset**: ordered column names plus rows of string values. Values stay strings at this
  layer; interpreting them belongs to the DuckDB type mapping above it.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a Linux host with no Windows component, no COM, no .NET runtime and no IIS
  anywhere in the path, a user can attach an Analysis Services instance and list its catalogs.
- **SC-002**: A metadata request whose response exceeds every splitting threshold at once —
  sealed frames, DIME records, and socket reads — returns the same row count as the HTTP
  binding returns for the same request and account.
- **SC-003**: The unit-test suite passes with sockets disabled on a machine that has never
  contacted an Analysis Services instance.
- **SC-004**: No committed file contains a hostname, address, account name, realm, SPN,
  machine name or security identifier, enforced by a gate that runs on every commit and scans
  every tracked file including binaries.
- **SC-005**: No *envelope builder* for a mutating command exists, asserted structurally
  rather than by inspection; and every statement reaching `Execute` is checked against a query
  allowlist, asserted by tests that feed it MDX writeback, DMX and `CALL` and require refusal.

  An earlier version of this criterion read "no code path exists through which the extension
  can mutate server state". That was false and the test that appeared to support it could not
  have failed: it asserted only that the emitted envelope lacked the literals `<Create`,
  `<Alter`, `<Delete` and `<Refresh`, none of which appear in any MDX or DMX mutation. The
  criterion is now split because the two halves have genuinely different strengths.
- **SC-006**: Every protocol claim in the documentation is either cited to a Microsoft Open
  Specification, backed by a committed fixture or a reproducible experiment, or marked
  UNVERIFIED.

## Assumptions

- **Verified today**: NTLM works end to end against SQL Server 2022, on both a tabular and a
  multidimensional named instance, in the reference implementation this specification is
  drawn from. A `DBSCHEMA_COLUMNS` response of 1366 rows exercised every splitting threshold.
- **Not verified**: Kerberos against a live Analysis Services instance. The only available
  fixture is a standalone workgroup machine, whose SSAS can therefore speak NTLM only.
  Kerberos questions that do not need SSAS — mechanism behaviour, token sizes, padding — are
  settled against an MIT KDC in CI instead, and the questions that remain are recorded as
  UNVERIFIED rather than assumed.
- The security layer's message protection is honoured as negotiated; the extension adds no
  encryption of its own design.
- Binary XML ([MS-BINXML]) and XPRESS compression are optional and negotiated, so they are
  excluded from this milestone. That single decision is what keeps the implementation small.
- Values are returned as strings from the protocol layer; the DuckDB type mapping is a
  separate concern layered above it.
- The extension targets Linux first. macOS is expected to work through the system GSS
  framework and is built in CI to catch BSD/Linux socket divergence early; Windows is not a
  goal, since a Windows user already has `msolap`.
