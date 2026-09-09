# Research: decisions, with what settled each

Constitution IV governs this file. Every entry says how it was settled: a specification
citation, a reproducible experiment, or neither — in which case it is marked **UNVERIFIED**
and code must not quietly depend on it.

The experiments below are reproducible from `test/gss/` and were run on 2026-09-09 against
`ubuntu:24.04`, MIT krb5 1.20.x and `gss-ntlmssp` 1.2.0-1build3.

---

## D1 — DIME framing is required, and its padding rule is the desync trap

**Decision**: Compose every message as DIME records; treat a record whose declared bytes have
arrived but whose padding has not as *incomplete*.

**Settled by**: [MS-SSAS] "TCP" — "When using TCP as the transport, the client and server MUST
compose messages by using Direct Internet Message Encapsulation [DIME]." The four length
fields exclude their own padding, so each of OPTIONS, ID, TYPE and DATA rounds separately.

**Why the padding rule is called out**: reporting such a record as decoded leaves the pad
bytes in the stream, where they are read as the next message's header and surface as
"unsupported DIME version" — a desync disguised as a protocol error, one message away from
its cause. Observed in the reference implementation.

---

## D2 — Negotiate clear-text `text/xml`; implement neither binary XML nor compression

**Decision**: Request neither. Raise a distinct negotiation error if the server selects
either anyway.

**Settled by**: [MS-SSAS] makes [MS-BINXML] and XPRESS optional and negotiated. Excluding
both is what keeps the implementation small.

**The trap**: setting the response-compression bit makes the server return XPRESS-compressed
XML. It arrives as convincing binary noise, not as an error. The reference Microsoft client
sets that bit; this extension must not, having no decompressor.

---

## D3 — The sealed frame

**Decision**:

    uint16 dataSize (LE) | uint16 tokenSize (LE) | ciphertext | token

**Ciphertext first, token second** — the inverse of GSS ordering.

**Settled by**: recovered from `Microsoft.AnalysisServices.AdomdClient`,
`TcpSecureStream.WriteHeader` and `TcpEncryptedStream.WriteInBlockMode` (finding cited per
the Provenance Boundary; no source reproduced). Independently corroborated by the reference
implementation completing a `Discover` over native TCP against a live instance once the byte
order was corrected.

**Not in [MS-SSAS]**: the specification does not document this layer at all. That is why the
citation is an experiment plus a named type, not a section number.

**Cost of getting it backwards**: the server closes the connection with no error and logs
nothing. Nine framing attempts failed before this was settled.

**Corollaries**:
- The UTF-8 BOM is sealed as its own frame before the body, because the reference client
  writes it through a writer whose encoding preamble is a separate write.
- `dataSize` is a `uint16`, so 65535 is a hard ceiling; a frame past it must be refused, not
  truncated.
- Neither size may be hardcoded. `tokenSize` is `max(cbSecurityTrailer, cbMaxSignature)`
  queried at runtime — 16 for NTLM, larger and etype-dependent for Kerberos (see D5).

---

## D4 — `gss_wrap_iov` is NOT available for NTLM. **This refutes the design's stated premise.**

**Status**: settled by experiment; the premise it replaces was wrong.

The project brief assumed `gss_wrap_iov` with detached buffers would serve both mechanisms,
mapping onto SSPI's `SECBUFFER_DATA`/`SECBUFFER_TOKEN` pair, and called this "the
load-bearing assumption of the whole design". It does not hold for NTLM.

**Experiment**: establish an NTLM context through the MIT mechglue with `gss-ntlmssp` and
call `gss_wrap_iov`.

**Result**: `GSS_S_UNAVAILABLE` (major `0x00100000`), "The operation or option is not
available or unsupported". This is not a mechglue routing fault — `gss-ntlmssp` 1.2.0
exports **no IOV entry points at all**:

    $ nm -D --defined-only gssntlmssp.so | grep -i iov
    (nothing)

Its exported surface is `gss_wrap`, `gss_unwrap`, `gss_wrap_size_limit`, `gss_get_mic`,
`gss_verify_mic` and the context/credential calls. So the mechglue's refusal is honest and
no version bump of the plugin is implied.

**What works instead**: plain `gss_wrap` under NTLM returns exactly

    token (16 bytes) || ciphertext (plaintext length)

which is the frame's two pieces already separated, just concatenated in the opposite order to
the wire. Measured across payloads of 1, 3, 60, 563, 2888, 4096 bytes:

| plaintext | wrapped | overhead | ciphertext length-preserving | frame round-trip |
|---|---|---|---|---|
| 1 | 17 | 16 | yes | ok |
| 3 | 19 | 16 | yes | ok |
| 60 | 76 | 16 | yes | ok |
| 563 | 579 | 16 | yes | ok |
| 2888 | 2904 | 16 | yes | ok |
| 4096 | 4112 | 16 | yes | ok |

`gss_wrap_size_limit(65535)` returns 65519, i.e. the same overhead of 16, so the split point
is derivable from the mechanism rather than hardcoded: `token_len = wrapped_len - plain_len`.
The first token observed was `01 00 00 00 | 12 2b df 89 01 f5 d0 b4 | 00 00 00 00 | <ct>` —
version, 8-byte checksum, 4-byte sequence, then the ciphertext, matching the documented NTLM
signature shape.

**Decision**: the sealing layer takes a `SealProvider` interface with two implementations —
one using `gss_wrap` plus a derived split (NTLM), one using `gss_wrap_iov` (Kerberos, D5).
Selection is by capability probe at context-establishment time, never by mechanism name, so a
future `gss-ntlmssp` that gains IOV support is picked up without a code change.

**Method note**: the first run of this experiment reported a broken round-trip. The cause was
in the probe, not the mechanism: `gss_unwrap`'s output buffer precedes `conf_state`, the
reverse of `gss_wrap`'s parameter order. Recorded because it is a trap the C++ port will meet
in the same place.

---

## D5 — `gss_wrap_iov` DOES give the frame layout under Kerberos, and pads for no AES etype

**Status**: settled by experiment against a real KDC. This closes most of what the reference
implementation had to leave open.

**Experiment**: MIT KDC in one container, realm `EXAMPLE.COM`, service principal
`MSOLAPSvc.3/<host>` holding a key of every supported enctype. Session-key enctype varied per
run via the client's `default_tgs_enctypes`, with the acceptor reading the same keytab.
Context requested `mutual | replay | sequence | conf | integ`, matching ADOMD's
`CalculateRequirements` on this path. Each run asserts which principal and which session-key
enctype it actually used.

**Result**: `gss_wrap_iov` with `HEADER | DATA | PADDING | TRAILER` succeeds for every AES
enctype, keeps DATA at plaintext length, and round-trips. Confidentiality is taken from the
mechanism's own `conf_state`, which is asserted at every size; the byte-comparison
cross-check is applied from 3 bytes up (see the method note below).

| session-key enctype | HEADER | TRAILER | token = H+T | PADDING |
|---|---|---|---|---|
| aes256-cts-hmac-sha1-96 | 32 | 28 | 60 | 0 |
| aes128-cts-hmac-sha1-96 | 32 | 28 | 60 | 0 |
| aes256-cts-hmac-sha384-192 | 32 | 40 | 72 | 0 |
| aes128-cts-hmac-sha256-128 | 32 | 32 | 64 | 0 |

Measured at payloads of 1, 3, 60, 563, 2888, 4096 and 65000 bytes; DATA was length-preserving
at every size and PADDING was zero at every size.

**A note on the method**: confidentiality is asserted from `conf_state`, the mechanism's own
report, at every size — it is deterministic and size-independent. It was being computed and
discarded while a byte-comparison stood in for it.

That byte comparison ("the ciphertext differs from the plaintext") is kept as a cross-check
but only from 3 bytes up. At 1 byte it is a coin flip rather than a measurement: the
ciphertext coincides with its plaintext once in 256 runs, and it duly did in CI, reporting
`NOT-ENCRYPTED` for aes128-cts-hmac-sha1-96 and failing the job. At 3 bytes the odds are
2⁻²⁴, comparable to the KDC container's own flake rate, so excluding more than the 1-byte row
would discard real measurement to buy nothing.

**Three findings**:

1. **Padding is zero for every AES enctype.** The reference implementation refuses a padding
   mechanism because the frame has no unpadded-length field, and kept that guard while noting
   the AES etypes were "expected" not to pad. They do not. The guard stays — it is cheap and
   it is the correct response if a non-AES enctype is ever negotiated — but it is no longer
   expected to fire.
2. **The 60-byte token the reference implementation used in its Kerberos-shaped test is
   exactly right** for aes256-cts-hmac-sha1-96, and wrong for the other three. Token size
   varies by enctype, so nothing may hardcode it — which FR-017 already required.
3. **A receiver can derive the header/trailer split without an enctype table.**
   `gss_wrap_iov_length` reports header and trailer sizes for a given data length on an
   established context, so on receive the frame's single `tokenSize` can be split into the two
   buffers `gss_unwrap_iov` needs. This is what makes a one-token wire field compatible with a
   two-buffer API.

**UNVERIFIED, and it is the remaining Kerberos question**: whether SSAS's SSPI places
HEADER-then-TRAILER contiguously in its single `SECBUFFER_TOKEN`, or rotates them (RFC 4121
RRC). We can produce and consume the concatenated form; we cannot confirm which form a real
Kerberos-speaking SSAS emits, because that needs a domain-joined instance and the available
fixture is a standalone workgroup machine. Recorded as unverified; not coded around.

**Rejected: `GSS_C_DCE_STYLE`.** It looked like MIT's switch to SSPI's single-buffer form.
Measured, it is not: it adds a handshake leg (2 client legs instead of 1) and *grows* the
trailer — 28 → 44 for aes256-cts-hmac-sha1-96, 56 for aes256-sha384 — rather than folding it
into the header. Not used.

---

## D6 — Sequence numbers are the mechanism's, not ours

**Decision**: let the GSS layer maintain its own counters; do not inject a sequence number.

**Settled by**: the reference client pre-increments its own `int` counters from 0, so the
first encrypt is passed 1 — but NTLM ignores the parameter and uses the context's internal
counter, which starts at 0. Confirmed in the D4 experiment: the first wrapped token carried
`00 00 00 00` in its sequence field.

---

## D7 — The `Authenticate` envelope uses a different namespace

**Decision**: `Authenticate` goes in the Analysis Services extension namespace, not the XMLA
namespace used by `Discover` and `Execute`.

**Settled by**: [MS-SSAS] "Authentication", and the hard way by a live server, which rejects
the XMLA namespace with "The Authenticate element ... cannot appear under Envelope/Body".

---

## D8 — The SPN form, and why the default departs from the reference client

**Decision**: default to the portless `MSOLAPSvc.3/<host>` form; offer the port and named
instance forms explicitly.

**Settled by**: partially. ADOMD's `CalculateNTAuthenticationSPN` calls `DsMakeSpn` *with* the
port, producing `MSOLAPSvc.3/<host>:<port>`. That justifies the string on **SSPI**, where the
SPN is used as written. On GSSAPI the host half goes through krb5 canonicalization and realm
determination, so a `host:2383` form leaves a trailing component no `[domain_realm]` mapping
can resolve — likely requesting a ticket in the wrong realm on exactly the platform this
extension exists for.

**Experiment**: a ticket for the port-suffixed SPN *is* obtainable when the KDC has it
registered, so the form is not inherently broken — the question is what a given site
registered, which is site configuration and not something to guess.

**UNVERIFIED**: which form a production SSAS registers by default. Neither form has been
tested against a live Kerberos-speaking instance. NTLM ignores the target entirely, which is
why the portless form has worked so far and proves nothing about Kerberos.

---

## D9 — No named-instance redirector

**Decision**: require a pinned port.

**Settled by**: the redirector on TCP 2382 has no public specification, and was verified
empirically not to speak the [MC-SQLR] framing that resolves database-engine instances on UDP
1434. The neighbouring `mssql-extension` does implement MC-SQLR — that is a different and
documented protocol, and its resolver does not transfer.

A firewall rule is needed either way, so pinning the port in `msmdsrv.ini` costs the operator
nothing, and a wrong guess presents as a hang.

---

## D10 — The byte seam, and why fixtures are synthesized

**Decision**: the protocol layer talks to a `Channel` interface with `send`/`recv`/`close`.
The real implementation wraps a socket; tests supply recorded bytes.

Handshake fixtures are **synthesized, never captured**. A real GSS/SPNEGO token carries the
principal, the realm, the target service and often the machine name; a committed capture
would be a disclosure that merely looks like an opaque blob, and no scrubber can reliably
redact arbitrary token structure. Captures of *post*-authentication traffic are permitted and
are scrubbed.

---

## D11 — macOS needs MIT krb5; Apple's GSS.framework cannot seal

**Status**: settled by inspection of the macOS SDK and the shipped framework binary, 2026-09-09.

The plan assumed macOS "is expected to work through the system GSS framework". It does not.

`GSS.framework`'s headers declare the IOV machinery — `gss_iov_buffer_desc`,
`GSS_IOV_BUFFER_TYPE_HEADER` and the rest — which makes the framework look capable at a
glance. But:

    $ nm -gU /System/Library/Frameworks/GSS.framework/GSS | grep -i wrap_iov
    (nothing)
    $ nm -gU /System/Library/Frameworks/GSS.framework/GSS | grep -ci ntlm
    0

There is no `gss_wrap_iov`, no `gss_unwrap_iov`, and no NTLM mechanism. The SDK also has no
`gssapi/gssapi_ext.h`, so code using the IOV API does not even compile against it.

Both seal providers are therefore unavailable on the framework: D5's needs `gss_wrap_iov`,
and D4's needs an NTLM mechanism to produce the `token || ciphertext` layout that makes the
length-delta split valid. A macOS build against the framework would configure, compile most
of the way, and then be unable to seal a single message.

**Decision**: macOS requires MIT krb5 (`brew install krb5`) discovered through pkg-config. The
framework is detected only so the configure-time failure can say why it was refused and what
to install. Accepting it would convert a build-time failure into a runtime one, which is
strictly worse.

**Consequence for the plan**: the macOS CI job is a *hermetic protocol test* job, not a client
build. That still serves its purpose — catching BSD/Linux socket divergence in `transport` —
because the protocol layer links no security library at all. `-DXMLA_REQUIRE_GSS=OFF` builds
exactly that target set, and constitution III already requires the suite to pass on a machine
that has never contacted an instance; it now also passes on one that has never had Kerberos.

---

## D12 — The NTLM path is verified end to end, in C++, against a live instance

**Status**: settled by a live run, 2026-09-09.

The spike (`tools/xmla_probe.cpp`) completed the whole path — TCP connect, DIME negotiation of
`text/xml`, the `Authenticate`/`AuthenticateResponse` loop, a sealed `Discover`, rowset parse
— against SQL Server 2022 Analysis Services on both a tabular and a multidimensional named
instance.

| request | rows | matches the reference implementation's recorded run |
|---|---|---|
| `DISCOVER_DATASOURCES` | 1 | yes |
| `DBSCHEMA_CATALOGS` | 1 | yes |
| `DBSCHEMA_TABLES` | 127 | yes |
| `DBSCHEMA_COLUMNS` | 1366 | yes |

1366 rows is past the sealed-frame, DIME-chunking and TCP-fragmentation thresholds at once,
which is why it is the number worth recording.

The provider that carried it was **`gss_wrap` with a derived token split** — the one that only
exists because D4 refuted the `gss_wrap_iov` premise. Had that assumption gone unchecked, this
run would have failed at the first sealed message, with the server closing the connection and
logging nothing.

**A defect this found, in the probe rather than the protocol**: `DISCOVER_DATASOURCES` answers
with the instance's own `DataSourceName`, which on a standalone box is `MACHINE\INSTANCE`. The
first run printed a real machine name to the terminal. Row *values* are now scrubbed on
output, not only fault text — anything a probe prints can be pasted into an issue.

**Still UNVERIFIED after this run**: everything Kerberos. The fixture is a standalone workgroup
machine, so its SSAS speaks NTLM only and no amount of live testing against it can settle D5's
token-layout question or D8's SPN form.
