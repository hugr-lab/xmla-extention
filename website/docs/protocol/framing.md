---
title: Framing
---

`[MS-SSAS]` requires **Direct Internet Message Encapsulation** on TCP:

> When using TCP as the transport, the client and server MUST compose messages
> by using Direct Internet Message Encapsulation [DIME].

A record is a 12-byte header — a 5-bit `VERSION` pinned to 1, the `MB`/`ME`/`CF`
/`TYPE_T` flags, then `OPTIONS`/`ID`/`TYPE`/`DATA` lengths — followed by those
four fields, **each padded separately to a 4-byte boundary**.

The declared lengths exclude their own padding, and that is the detail that makes
a naive reader desync. A record whose payload has arrived but whose padding has
not is *incomplete*, not decoded. Reporting it as decoded leaves the pad bytes in
the stream, where they are read as the next message's header and surface as a
bogus "unsupported DIME version" — a desync disguised as a protocol error, one
message away from its cause.

## Reassembly

Framing is not message boundaries. A peer may split one message across several
reads, or pack several messages into one segment. The reader is driven by the
header's declared lengths, keeps a buffer across calls, and consumes exactly one
message at a time.

Incompleteness is signalled by a **distinct type**, never by inspecting an error
message. Detecting "need more bytes" by substring-matching was a real defect: a
chunked message split at a record boundary raises a different message and was
treated as fatal.

## Content-type negotiation

Content type is negotiated through the first `OPTIONS` byte. Binary XML
(`[MS-BINXML]`) and XPRESS compression are optional, so this extension requests
neither and implements neither. That single decision is what keeps it small.

One bit matters more than it looks. Setting `RESP_XPRESS` makes the server return
XPRESS-compressed XML, which arrives as convincing binary noise rather than an
error. The reference Microsoft client sets it; this one must not, having no
decompressor. If a server selects an encoding the client did not ask for, the
negotiation check refuses it **loudly** — a refusal is a scope change to report,
not a fallback to absorb.
