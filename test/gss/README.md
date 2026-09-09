# GSS mechanism probes

These are not unit tests. They are the reproducible experiments behind
`specs/001-xmla-tcp-binding/research.md` D4 and D5 — the questions that decide how the
sealing layer is built and that cannot be answered by reading a specification, because no
specification documents the sealed frame.

Each probe answers one question and prints its own verdict.

## `ntlm/` — is `gss_wrap_iov` usable for NTLM?

    docker build --platform linux/amd64 -t xmla-gss-ntlm test/gss/ntlm
    docker run --rm --platform linux/amd64 xmla-gss-ntlm

`wrap_iov_availability.c` establishes an NTLM context through the MIT mechglue and calls
`gss_wrap_iov`. Expected result: **it fails** with `GSS_S_UNAVAILABLE`, because
`gss-ntlmssp` exports no IOV entry points. This refutes the premise the project started
from, so it is kept as an executable statement of that fact rather than a note in prose.

`wrap_split.c` then shows what works instead: plain `gss_wrap` returns
`token || ciphertext` with the ciphertext at plaintext length, and rebuilds the SSAS frame
from it to prove the split is exact. It fails loudly if the overhead is not constant or the
ciphertext is not length-preserving.

## `kerberos/` — what does `gss_wrap_iov` do under a real KDC?

    docker build --platform linux/amd64 -t xmla-gss-krb test/gss/kerberos
    docker run --rm --platform linux/amd64 xmla-gss-krb

Stands up an MIT KDC in the container, then measures HEADER/DATA/PADDING/TRAILER sizes once
per session-key enctype. This is how the Kerberos questions get settled without SSAS: the
mechanism's behaviour is a property of the mechanism, and a krb5 acceptor holding the service
keytab answers it. No Analysis Services instance is involved and none could be — SSAS has no
Linux build.

Three traps are guarded inside the script, each of which produced a confident wrong answer
during development and would do so again:

- `dns_canonicalize_hostname` collapses several test hostnames sharing one loopback address
  to the first name in `/etc/hosts`, so every run silently uses the same principal. The runs
  looked like four enctypes and were one enctype four times.
- Varying the *service key* enctype varies the *ticket* enctype, not the session key. The
  session key — the one the wrap uses — comes from the client's `default_tgs_enctypes`.
- Narrowing `permitted_enctypes` to force an enctype also stops the acceptor reading its own
  keytab. That surfaces as "found in keytab but cannot decrypt ticket", which looks like a
  protocol result and is not one.

Each run therefore asserts which principal and which session-key enctype it actually used,
and says so when they differ from what was asked for.

## What these do not prove

Nothing here involves Analysis Services. They settle what the *mechanism* does. Whether a
Kerberos-speaking SSAS lays its single token buffer out the same way we assemble ours is
recorded as UNVERIFIED in research.md D5, and no code here assumes an answer.
