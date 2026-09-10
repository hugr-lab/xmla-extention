---
title: Sealing
---

Every message after the handshake is sealed with the negotiated security context
and wrapped in a 4-byte header:

```
uint16  dataSize    little-endian, the ciphertext length
uint16  tokenSize   little-endian, the security token length
bytes   ciphertext  dataSize bytes
bytes   token       tokenSize bytes
```

**Ciphertext first, token second.** That is the inverse of GSS-API ordering, and
getting it backwards is silently fatal: the server closes the connection with no
error and logs nothing. Nine framing attempts failed before this settled.

`[MS-SSAS]` does not document this layer at all. It was established by studying
how Microsoft's own client frames these messages, and is recorded here as a
**finding** about the wire format rather than as code — nothing third-party is
copied into or shipped with this project.

Two details that cost days to rediscover:

- The UTF-8 **BOM is sealed as its own frame** before the body, because the
  reference client writes it through a writer whose encoding preamble is a
  separate write. This client emits it because the reference client does; whether
  the server *requires* it is **untested**, because the exchange that first
  worked fixed two faults at once.
- The hard ceiling is 65535, since `dataSize` is a `uint16`. The per-mechanism
  chunk size is smaller and comes from the provider; smaller chunks are always
  valid, just more frames.

## Two seal providers, chosen by capability

The frame wants the ciphertext at plaintext length and the token detached. SSPI
hands ADOMD exactly that as a `SECBUFFER_DATA`/`SECBUFFER_TOKEN` pair. GSS-API
has two ways to produce it and **neither works for both mechanisms**:

| mechanism | route | why not the other one |
|---|---|---|
| Kerberos | `gss_wrap_iov` with HEADER/DATA/PADDING/TRAILER | plain `gss_wrap` encrypts the plaintext *inside* the token under RRC rotation — no fixed offset to slice at |
| NTLM | `gss_wrap`, split at `wrapped_len - plain_len` | `gss-ntlmssp` exports **no IOV entry points at all**, so `gss_wrap_iov` returns `GSS_S_UNAVAILABLE` |

Selection is a **capability probe**, never a mechanism-name switch, so a future
`gss-ntlmssp` that gains IOV support is picked up without a code change.

On receive, the IOV provider recovers the header/trailer split with
`gss_wrap_iov_length` rather than a table of per-enctype sizes. That is what
makes one wire token field compatible with a two-buffer API without hardcoding
anything.

## What was settled against a real KDC

Measured against an MIT KDC in CI, across four AES session-key enctypes:

- `gss_wrap_iov` gives the detached split, keeps DATA at plaintext length, and
  **pads for none of them**. The reference implementation kept a padding guard
  while noting the AES etypes were "expected" not to pad; they do not.
- Token size is 60, 64 or 72 bytes depending on the session key, so nothing may
  hardcode it. The reference implementation's Kerberos-shaped test used 60,
  which is right for exactly one enctype.
- A receiver can derive the header/trailer split from `gss_wrap_iov_length`,
  without an enctype table.
- `GSS_C_DCE_STYLE` is *not* the switch to SSPI's single-buffer form: it adds a
  handshake leg and grows the trailer instead of folding it into the header.
