# Spec quality checklist

- [x] Every functional requirement is testable without a live server, or says why not.
- [x] Every protocol claim is cited to [MS-SSAS], to a committed experiment, or marked
      UNVERIFIED. (research D3 cites experiments because the specification is silent on the
      sealed frame; D5 and D8 carry explicit UNVERIFIED markers.)
- [x] Read-only is stated as absence of capability, not as a gate.
- [x] No requirement names a host, account, realm or address.
- [x] The three splitting layers are each specified separately, and their composition is
      required to be tested.
- [x] "Needs more bytes" and "malformed" are required to be distinct types, not distinguished
      by message text.
- [x] Success criteria are measurable and technology-agnostic.
- [ ] Kerberos acceptance scenarios cannot be closed against a live instance. Deliberate: the
      available fixture is a standalone workgroup machine. The mechanism-level questions are
      closed in CI against an MIT KDC instead; the SSAS-level question stays open.
