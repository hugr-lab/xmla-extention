# Architecture

A DuckDB extension that reads SQL Server Analysis Services over the **native XMLA/TCP
binding**, from Linux, with no IIS, no COM and no Windows components.

## Why this exists

SSAS speaks XMLA over two bindings: HTTP through the `msmdpump` ISAPI extension hosted in
IIS, and a native TCP binding. Every existing client for the native one is Windows-only —
ADOMD.NET and the MSOLAP OLE DB provider are COM/.NET, and DuckDB's own `msolap` extension
states Windows-only support because of those COM dependencies. A Linux consumer that wants
SSAS metadata must therefore stand up IIS in front of every instance.

This extension removes that requirement.

## The layers

Strictly bottom-up: no lower layer includes a higher one.

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

`sealing`, `envelopes`, `rowset`, `redact` and `errors` are leaves used across layers.

**Sealing is deliberately not in that stack.** The handshake is sent *unsealed*, and sealing
is applied by the client to every message after it, on the way into the transport. Drawing it
between `auth` and `transport` reads as though the handshake passed through it, which it does
not.

`src/xmla/` carries **no DuckDB include and links no security library**. That is not tidiness:
it is what makes the test suite runnable on a machine that has never contacted an Analysis
Services instance, and it is enforced by the linker rather than by review. When `client.cpp`
briefly called `GssContext::Create` directly, the link failed — which is the property working.

## `dime` — framing

[MS-SSAS] requires Direct Internet Message Encapsulation on TCP. A record is a 12-byte header
— a 5-bit VERSION pinned to 1, the MB/ME/CF/TYPE_T flags, then OPTIONS/ID/TYPE/DATA lengths —
followed by those four fields, **each padded separately to a 4-byte boundary**. The declared
lengths exclude their own padding, which is the detail that makes a naive reader desync: a
record whose payload has arrived but whose padding has not is *incomplete*, not decoded.
Reporting it as decoded leaves the pad bytes in the stream, where they are read as the next
message's header and surface as a bogus "unsupported DIME version" — a desync disguised as a
protocol error, one message from its cause.

Content type is negotiated through the first OPTIONS byte. Binary XML ([MS-BINXML]) and XPRESS
compression are optional, so this extension requests neither and implements neither. That
single decision is what keeps it small.

## `transport` — reassembly

Framing is not message boundaries. A peer may split one message across several reads, or pack
several messages into one segment. The reader is driven by the header's declared lengths,
keeps a buffer across calls, and consumes exactly one message at a time.

Incompleteness is signalled by a distinct `IncompleteMessage` type, never by inspecting an
error message. Detecting "need more bytes" by substring-matching was a real defect: a chunked
message split at a record boundary raises a different message and was treated as fatal.

## `sealing` — the post-authentication frame

Every message after the handshake is sealed and wrapped in a 4-byte header:

    uint16 dataSize | uint16 tokenSize | ciphertext | token

**Ciphertext first, token second** — the inverse of GSS ordering. Getting it backwards is
silently fatal: the server closes the connection with no error and logs nothing. [MS-SSAS]
does not document this layer at all; it was recovered from `AdomdClient`'s
`TcpSecureStream.WriteHeader` and `TcpEncryptedStream.WriteInBlockMode`, and is cited as a
finding rather than reproduced as code (see the constitution's Provenance Boundary).

Two details that cost days to rediscover:

- The UTF-8 BOM is sealed as its **own frame** before the body, because the reference client
  writes it through a writer whose encoding preamble is a separate write.
- Requesting response compression makes the server return XPRESS-compressed XML, which arrives
  as convincing binary noise rather than an error. The reference client sets that bit; this
  one must not, having no decompressor.

### Two seal providers, chosen by capability

The frame wants the ciphertext at plaintext length and the token detached. SSPI hands ADOMD
exactly that as a `SECBUFFER_DATA`/`SECBUFFER_TOKEN` pair. GSS-API has two ways to produce it
and **neither works for both mechanisms**:

| mechanism | route | why not the other one |
|---|---|---|
| Kerberos | `gss_wrap_iov` with HEADER/DATA/PADDING/TRAILER | plain `gss_wrap` encrypts the plaintext *inside* the token under RRC rotation — no fixed offset to slice at |
| NTLM | `gss_wrap`, split at `wrapped_len - plain_len` | `gss-ntlmssp` exports **no IOV entry points at all**, so `gss_wrap_iov` returns `GSS_S_UNAVAILABLE` |

Selection is a **capability probe**, never a mechanism-name switch, so a future `gss-ntlmssp`
that gains IOV support is picked up without a code change.

On receive, the IOV provider recovers the header/trailer split with `gss_wrap_iov_length`
rather than a table of per-enctype sizes. That is what makes one wire token field compatible
with a two-buffer API without hardcoding anything.

## `auth` — the handshake

[MS-SSAS] carries GSS-API security tokens **inside SOAP**: `Authenticate` out,
`AuthenticateResponse` back, repeating until the mechanism reports completion. One loop serves
Kerberos and NTLM because the specification's exchange is mechanism-agnostic.

`Authenticate` uses a **different namespace** from Discover and Execute —
`http://schemas.microsoft.com/analysisservices/2003/ext`, not the XMLA namespace. A live
server rejects the wrong one outright.

Every authenticate response is fault-checked, **including the terminal one**. For NTLM the
client context completes as it emits its last token, so a handshake that returns without
inspecting that reply silently drops a "Logon failure" and reports success.

## `client` — session and errors

Sequences negotiate → authenticate → request, captures the `SessionId` the server returns to
`BeginSession` and carries it on every later request, and maps faults onto categories a caller
can act on without parsing text.

`Credential` has **no password field**. Where NTLM needs one on a standalone server it is
passed to the security layer directly and never retained.

## How messages get split

Three independent splits can apply to one message, each handled at a different layer, and they
compose. Getting this wrong corrupts large rowsets specifically — the case least likely to be
exercised by a first test.

1. **Sealed-frame chunking** (`sealing`) — a payload longer than the chunk size becomes several
   frames, each with its own header, ciphertext and token.
2. **DIME record chunking** (`dime`) — a message too large for one record is split across
   several, `CF` set on all but the last, `MB` on the first, `ME` on the last. Per [MS-SSAS] a
   chunked sequence is contained within one message and never spans messages.
3. **TCP fragmentation** (`transport`) — reads driven by declared lengths, buffer held across
   calls.

A test composes all three at once — a 400-row document cut into ~500 sealed frames inside ~130
DIME records over ~1300 reads — rather than relying on a response that happens to trigger two
of them.

## Testability: the byte seam

`Channel` is an interface with `send`/`recv`/`close`. The real implementation wraps a socket;
tests supply recorded bytes. Everything above the socket is therefore ordinary unit-testable
code, and the suite runs with no server, no stub to keep in sync, and no security library.

Handshake fixtures are **synthesized, never captured**. A real GSS/SPNEGO token carries the
principal, the realm, the target service and often the machine name; a committed capture would
be a disclosure that merely looks like an opaque blob, and no scrubber can reliably redact
arbitrary token structure.

## Addressing

Instances are addressed by host and a **pinned port**. The named-instance redirector on TCP
2382 is not used: its wire format has no public specification, and it was verified empirically
not to speak the [MC-SQLR] framing that resolves database-engine instances on UDP 1434. (The
neighbouring `mssql-extension` does implement MC-SQLR — a different, documented protocol whose
resolver does not transfer.) A firewall rule is needed either way, so pinning the port costs
the operator nothing, and a wrong guess presents as a hang.

## Current status

**Working over NTLM, verified end to end.** The spike completes discovery against a live SQL
Server 2022 instance on both a tabular and a multidimensional named instance;
`DBSCHEMA_COLUMNS` returns 1366 rows, past every splitting threshold at once.

**Kerberos is expected to work and is UNVERIFIED against a live server.** What is settled, and
what is not:

*Settled against a real MIT KDC* (`test/gss/kerberos/`), across four AES session-key enctypes:

- `gss_wrap_iov` gives the detached split, keeps DATA at plaintext length, and **pads for
  none of them**. The reference implementation kept a padding guard while noting the AES
  etypes were "expected" not to pad; they do not.
- Token size is 60, 64 or 72 bytes depending on the session key, so nothing may hardcode it.
  The reference implementation's Kerberos-shaped test used 60, which is right for exactly one
  enctype.
- A receiver can derive the header/trailer split from `gss_wrap_iov_length`, without an
  enctype table.
- `GSS_C_DCE_STYLE` is *not* the switch to SSPI's single-buffer form: it adds a handshake leg
  and grows the trailer instead of folding it into the header.

*Not settled*: whether a Kerberos-speaking SSAS concatenates HEADER and TRAILER in its single
token buffer the way we do, or rotates them (RFC 4121 RRC). That needs a domain-joined
instance; the available fixture is a standalone workgroup machine whose SSAS can only do NTLM.
Also unsettled is which SPN form a production instance registers — the portless form GSSAPI
builds, or the port-suffixed form ADOMD's `DsMakeSpn` produces. NTLM ignores the target
entirely, which is why the portless form has worked so far and proves nothing about Kerberos.

**macOS needs MIT krb5.** Apple's `GSS.framework` declares the IOV types but exports neither
`gss_wrap_iov` nor any NTLM mechanism, so it cannot seal a message. It is detected only so the
configure-time failure can say what to install.
