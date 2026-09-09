# Data model

Entities the protocol layer owns, and the invariant that makes each one worth having as a
type rather than a parameter.

## ConnectionTarget

`host: string`, `port: uint16`, `timeout: duration`.

- **No default port.** A default invites guessing between a default instance's well-known
  port and a named instance's pinned one, and guessing wrong presents as a hang rather than
  as an error.
- `timeout` must be positive. There is no value meaning "wait forever" (FR-025).

## Credential

`mechanism` (kerberos | negotiate | ntlm), `principal?`, `service = "MSOLAPSvc.3"`,
`instance?`, `use_port = false`, `spn?`.

- **No password field.** Where NTLM needs one on a standalone server it goes straight to the
  security layer and is never retained, so no formatting or logging of a `Credential` can
  leak it (FR-014).
- `target(host, port)` composes the SPN. Default is the portless form; see research D8 for
  why that departs from the reference client, and why the departure is deliberate on GSSAPI.
- An unknown mechanism is rejected, not coerced. Silently mapping a typo onto NTLM
  authenticates with a mechanism the caller did not ask for.

## NegotiatedTerms

`content_type`, `request_binary`, `response_binary`, `request_compressed`,
`response_compressed`, `protection`.

Settled once per session and immutable thereafter. The extension asks for clear-text
`text/xml` and no compression; a server that selects otherwise raises rather than being
accommodated (FR-009).

## SealContext

The negotiated security context plus the provider chosen for it.

- `provider` is selected by **capability probe**, not by mechanism name: try `gss_wrap_iov`,
  fall back to `gss_wrap` with a derived split. `gss-ntlmssp` exports no IOV entry points
  today (research D4); a future version that does is then picked up without a code change.
- `token_len` is never stored as a constant. On send it is the actual token length; on
  receive it is the header's declared value (FR-017).

## SealedFrame

`data_size: uint16`, `token_size: uint16`, `ciphertext`, `token`.

- Ciphertext first, token second — the inverse of GSS ordering (FR-016).
- Either size exceeding `uint16` is refused, never truncated (FR-020).
- A buffer ending mid-frame — including a 1–3 byte partial header — is *incomplete*, not
  malformed. These are distinct types because the transport discriminates on exactly that,
  and conflating them breaks every rowset larger than one read (FR-003, FR-004).

## Session

`target`, `credential`, `terms`, `state`, and privately the stream, the security context, the
scrubber, the server's session id, and whether the first record has been sent.

State machine: `UNCONNECTED → NEGOTIATED → AUTHENTICATED → CLOSED`, with `FAILED` reachable
from any of them.

- **Everything connection-scoped resets on open** (FR-024). A reconnect that keeps the
  negotiation bit or the session id from a dead connection is silently fatal: the server
  closes the connection with no error and logs nothing.
- The old stream is closed before it is replaced. Overwriting it leaks the socket for the
  life of the process and leaves the server-side session open — in exactly the reconnect path
  the reset exists to support.

## Rowset

`columns: ordered list of names`, `rows: list of name → string`.

Values stay strings. Interpreting them is the DuckDB type mapping's job, one layer up, and
doing it here would put a type system in the protocol layer.

An **empty rowset is a meaningful answer** — "no catalogs visible to this account" is
distinct from "access refused". That is why a response which does not decrypt to XML must
raise rather than parse to empty (FR-022): the likeliest cipher-layer failure produces
exactly that indistinguishable emptiness.

## Error categories

`Connection`, `Authentication`, `Authorization`, `Negotiation`, `Server`, `Protocol`, and
`IncompleteMessage` as a subtype of `Protocol`.

Distinct types rather than one error with a code, because they demand different operator
actions: check the network, check the ticket, check permissions, report a scope change, read
the server's explanation, file a bug. Collapsing them forces callers to parse text (FR-029).

`detail` carries the server's own explanation where one exists, scrubbed before it arrives
(FR-030).
