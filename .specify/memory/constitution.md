<!--
Sync Impact Report
- Version change: (none) → 1.0.0  (initial ratification for this project)
- Derived from the ssas-xmla-tcp constitution v1.0.0. All five principles carry
  over; II and III are widened from "library" to "extension", and IV gains the
  decompile-boundary clause that a C++ port makes newly load-bearing.
- Principles defined: I No Secret Leakage; II Read-Only by Construction;
  III Offline-First Hermetic Tests; IV Spec-Governed Protocol Work;
  V Spec-Driven with Review Gates
- Added sections: Security & Data-Handling Constraints; Provenance Boundary;
  Development Workflow & Quality Gates
- Carried over unchanged: the leak-gate hook, the synthesized-fixture rule, the
  no-Windows-component rule (which is this project's entire reason to exist).
- Deferred TODOs: none
-->

# xmla Constitution

## Core Principles

### I. No Secret Leakage (NON-NEGOTIABLE)

Credentials, hostnames, addresses, account names, realm and domain names, service principal
names, machine/NetBIOS names and security identifiers MUST come only from the environment or
a gitignored file, and MUST NEVER appear in a committed file, test fixture, log line, error
message or commit message.

This binds harder here than in a text protocol. Captured fixtures are **raw bytes of an
authenticated session**, and a GSS-API/SPNEGO token is a structured object carrying the
principal, the realm, the target service and often the machine name. A committed handshake
capture is therefore a disclosure unless every token is either synthesized or scrubbed. A
fixture containing a real security token MUST NOT be committed under any circumstance, and
the scrub MUST be re-verified whenever fixtures are regenerated.

Rationale: a byte-level capture looks opaque and is not. Treating binary fixtures as
inherently safe is the specific mistake this principle exists to prevent.

### II. Read-Only by Construction

The extension MUST expose no operation that creates, alters, refreshes or deletes a
server-side object. This is a property of what the code contains, not of what callers
choose to call: an operation that could mutate server state MUST NOT exist in the codebase,
so no configuration, argument or mistake can reach one.

For a DuckDB extension this extends to the catalog surface: the attached catalog MUST
refuse DDL and DML rather than translating it, and no `COPY TO`, `INSERT`, `UPDATE`,
`DELETE` or `CREATE` path may be registered. A test asserts the absence structurally, so
the capability cannot arrive unnoticed.

Rationale: the extension authenticates with real domain credentials against production
analytic servers. Absence of the capability is the only guarantee that survives misuse.

### III. Offline-First Hermetic Tests (NON-NEGOTIABLE)

Unit tests MUST run with sockets disabled against recorded or synthesized byte-level
fixtures and MUST NOT depend on any server being reachable. A unit-test run MUST pass on a
machine that has never contacted an Analysis Services instance. Live servers are for
integration and acceptance runs only, and those MUST be separable from the default suite.

The protocol layer MUST therefore carry no DuckDB dependency and MUST be reachable through a
byte-level seam (a channel interface with `send`/`recv`/`close`) that a test can supply
recorded bytes to.

Rationale: the target is a credentialed server inside someone's network. A suite that needs
it is not reproducible, cannot run in CI, and cannot be run by a contributor at all.

### IV. Spec-Governed Protocol Work

Every byte the extension emits or accepts MUST be traceable to normative text in the
Microsoft Open Specifications, cited at the point of implementation. Blog posts, forum
answers and inference from other implementations are not sources.

Where the specification is silent — which it is for the entire post-authentication sealed
frame — the claim MUST be traceable to a recorded fixture or to a named, reproducible
experiment, and MUST be marked **UNVERIFIED** in prose until it is. An assumption presented
as fact is a defect, and a protocol claim with neither a citation nor a fixture MUST be
written as unverified rather than stated.

Where observed bytes and the specification disagree, the observation wins and MUST be
recorded as a fixture with the divergence documented against the spec section it
contradicts — the specification's own product-behaviour appendix is the first place to look
before concluding the document is wrong.

Rationale: this is a clean-room implementation of an undocumented-in-practice binding. Its
only defensible foundation is the published specification plus recorded evidence of what a
real server does.

### V. Spec-Driven with Review Gates

Work MUST proceed through the spec-kit pipeline (constitution → specify → clarify → plan →
tasks). Each implementation task MUST be committed on its own and reviewed before the next
begins.

Rationale: small reviewed increments catch defects early and keep spec and code aligned.

## Provenance Boundary

Understanding of the sealed frame was recovered by decompiling a Microsoft client assembly.
That material is a **reference for understanding only**.

- No decompiled source, IL listing, or verbatim extract of it may be copied, vendored,
  committed, or quoted at length in this repository.
- Findings — a field layout, a byte order, a size, a control-flow fact — may be recorded and
  cited, because a fact about a wire format is not the expression that revealed it.
- Where a finding is cited, the citation names the type and member it came from so a reader
  can verify it independently, without reproducing the code.

Rationale: the reference repository holds findings and never decompiled source. That
boundary is what makes this work distributable, and it does not survive being blurred once.

## Security & Data-Handling Constraints

- Credentials reach the extension from the environment, a ticket cache or a keytab. The
  extension MUST NOT read, write or persist a credential itself.
- Security tokens MUST NEVER be logged, at any level, in any form — not truncated, not
  hashed, not base64. The same applies to raw message bodies until they have been scrubbed.
- The extension MUST NOT require any Windows-only or .NET component, on any platform. This
  is the gap the project exists to close: the existing `msolap` extension is Windows-only
  because it binds COM/OLE DB, and reproducing that dependency would forfeit the whole point.
- Where the security layer negotiates message protection, the extension MUST honour it and
  MUST NOT substitute or add encryption of its own design.
- The dependency surface MUST stay minimal. GSSAPI/krb5 is the only native dependency the
  protocol layer may acquire; sealing is done by the security context, so no TLS library is
  needed and none may be added for that purpose.

## Development Workflow & Quality Gates

- The leak-gate hook (`.githooks/pre-commit`) runs on every commit; a finding is a hard block,
  never bypassed for convenience.
- Regenerating fixtures MUST re-run the leak check, and a non-zero identifying-token count is
  a release blocker.
- Every commit is small and scoped to one task.
- A change that weakens a NON-NEGOTIABLE principle MUST be rejected in review.
- Unverified protocol claims MUST be marked as such in documentation until a fixture settles
  them.

## Governance

This constitution supersedes other practices for this project. Amendments MUST be recorded in
this file with a Sync Impact Report and a semantic-version bump: MAJOR for removing or
redefining a principle, MINOR for adding a principle or materially expanding guidance, PATCH
for clarifications that change no requirement.

**Version**: 1.0.0 | **Ratified**: 2026-09-09 | **Last Amended**: 2026-09-09
