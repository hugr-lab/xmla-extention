"""Build a vcpkg overlay port for krb5 whose ONLY change is where autoconf puts
sysconfdir and localstatedir.

vcpkg_make_common.cmake passes --prefix and nothing else, so both default to
${prefix} -- the vcpkg install tree. krb5 bakes them into the library at
configure time (osconf.hin: MECH_CONF is "@SYSCONFDIR/gss/mech",
DEFAULT_PLUGIN_BASE_DIR is "@LIBDIR/krb5/plugins", and configure.ac derives the
default client keytab from localstatedir), so the shipped binary looks for the
host's configuration inside a directory that only ever existed on the builder.

Pointing them at /etc and /var is one option each and is arm C of the probe.
"""

import pathlib
import sys

ANCHOR = "            --disable-nls\n            --with-tls-impl=no"
ADDED = "\n            --sysconfdir=/etc\n            --localstatedir=/var"


def main() -> int:
    portfile = pathlib.Path(sys.argv[1]) / "portfile.cmake"
    text = portfile.read_text()
    if ANCHOR not in text:
        # Fail loudly: silently not patching would make arm C a duplicate of
        # arm B and the probe would report a fix that was never applied.
        print(f"FAIL: the OPTIONS block in {portfile} has moved; refusing to "
              f"produce an overlay that silently changes nothing", file=sys.stderr)
        return 1
    if text.count(ANCHOR) != 1:
        print(f"FAIL: {ANCHOR!r} is not unique in {portfile}", file=sys.stderr)
        return 1
    portfile.write_text(text.replace(ANCHOR, ANCHOR + ADDED))
    print(f"patched {portfile}: sysconfdir=/etc localstatedir=/var")
    return 0


if __name__ == "__main__":
    sys.exit(main())
