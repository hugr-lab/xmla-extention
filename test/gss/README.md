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

## `vcpkg-mech/` — does a vcpkg-built krb5 still see the host's NTLM mechanism?

    docker build --platform linux/amd64 -t xmla-gss-vcpkg test/gss/vcpkg-mech
    docker run --rm --platform linux/amd64 xmla-gss-vcpkg

`vcpkg.json` declares krb5 for one consumer: the community-extensions registry, which builds
through vcpkg and has no system krb5. That changes what a published artifact contains, and
this probe measures the consequence. Three arms, same container, same `gss-ntlmssp`, differing
only in which krb5 provides the mechglue — system, vcpkg, and vcpkg with `--sysconfdir=/etc`.

Result: **a vcpkg-built krb5 does not register NTLM.** MIT krb5 bakes `MECH_CONF` from
autoconf's `sysconfdir` at configure time (`osconf.hin`: `"@SYSCONFDIR/gss/mech"`), and
`vcpkg_make_common.cmake` passes only `--prefix`, so the shipped library looks for mechanism
plugins in `<builder>/vcpkg_installed/<triplet>/etc/gss/mech` — a directory that existed only
on the machine that built it. `gss-ntlmssp` installs into the host's `/etc/gss/mech.d`, and
`mechglue/Makefile.in` sets `_GSS_STATIC_LINK`, so krb5 and SPNEGO are compiled in and NTLM
can arrive from nowhere else. The probe reports it as `GSS_S_BAD_MECH` against
`GSS_S_FAILURE` for a mechanism that is present and merely has no credential to offer.

NTLM is the only path this project has verified end to end, and the registry listing's own
`hello_world` uses `MECHANISM 'ntlm'`, so this is the difference between shipping the feature
and shipping a binary that refuses it on every machine.

Two fixes exist, which is why the arms are there rather than a single failing assertion:

- **Build time**: `--sysconfdir=/etc` on the port. One option, and arm C shows it restores the
  mechanism. It also fixes `DEFAULT_PLUGIN_BASE_DIR` and the default client-keytab path, which
  come from the same defaulted directories.
- **Run time**: `GSS_MECH_CONFIG` pointed at the host's file. It names a single file and
  replaces the configuration rather than adding to it, which is survivable only because
  `_GSS_STATIC_LINK` compiles krb5 and SPNEGO in. This is the only lever available to someone
  who already has a published artifact.

Worth recording, because it was the natural assumption and it is wrong: the static mechglue
loads a system `.so` plugin perfectly well. Nothing about static linking is the problem — the
baked path is the whole of it.

### The registry cannot currently build this port at all

Separately from the mechanism question, and found while building this probe: `vcpkg-make`
requires `autoconf-archive` on the build host. Not because krb5 needs its macros — krb5
vendors `ax_pthread.m4` and `ax_recursive_eval.m4` — but because `vcpkg_make.cmake` runs
`aclocal --dry-run` over its own `configure.ac`, greps stderr for `autoconf-archive`, and
raises `FATAL_ERROR` when it is missing. It therefore gates every vcpkg autotools port on
Linux.

The registry builds Linux in `quay.io/pypa/manylinux_2_28_{x86_64,aarch64}` (AlmaLinux 8.10),
which ships `autoconf`, `automake`, `libtool`, `aclocal` and `bison` but **not**
`autoconf-archive`, and `extension-ci-tools/scripts/ci_phase.py` installs it only in
`setup_macos` (via brew) and not in `setup_linux`. macOS, the one platform whose setup would
provide it, is in this extension's `excluded_platforms`. `requires_toolchains` has no autotools
option, and `custom_toolchain_script` is read by `community-extensions/scripts/build.py` and
never written anywhere, so `description.yml` offers no lever either.

This probe therefore measures what the artifact *would* do on the assumption that the build is
somehow made to succeed. It is not the registry's environment, and deliberately so: the control
arm needs a system krb5 to compare against.

## What these do not prove

Nothing here involves Analysis Services. They settle what the *mechanism* does. Whether a
Kerberos-speaking SSAS lays its single token buffer out the same way we assemble ours is
recorded as UNVERIFIED in research.md D5, and no code here assumes an answer.
