#!/usr/bin/env bash
# Runs the three arms and prints one verdict. Exits non-zero when a vcpkg-built
# krb5 cannot see the host's NTLM mechanism, so this can gate a submission.
set -u

run() { printf '%s\n' "--- $1 ---"; "$2"; local rc=$?; echo; return $rc; }

run "arm A: system krb5 (the control)"          /mechs_system; a=$?
run "arm B: vcpkg krb5, static"                 /mechs_stock;  b=$?
run "arm C: vcpkg krb5, --sysconfdir=/etc"      /mechs_fixed;  c=$?

# GSS_MECH_CONFIG names a single file and replaces the config rather than adding
# to it. krb5 and SPNEGO survive that because _GSS_STATIC_LINK compiles them in,
# which is why this works at all -- worth measuring, since it is the only lever
# available to someone who already has a published artifact.
printf '%s\n' "--- arm B again, with GSS_MECH_CONFIG set at runtime ---"
GSS_MECH_CONFIG=/etc/gss/mech.d/mech.ntlmssp.conf /mechs_stock; d=$?
echo

state() { [ "$1" -eq 0 ] && echo REGISTERED || echo ABSENT; }
echo "=================== verdict ==================="
printf '  %-34s %s\n' "A  system krb5"                 "$(state $a)"
printf '  %-34s %s\n' "B  vcpkg krb5"                  "$(state $b)"
printf '  %-34s %s\n' "C  vcpkg krb5, sysconfdir=/etc" "$(state $c)"
printf '  %-34s %s\n' "B + GSS_MECH_CONFIG"            "$(state $d)"
echo

if [ $a -ne 0 ]; then
	echo "INCONCLUSIVE: the control did not register NTLM, so this container"
	echo "cannot answer the question. Check that gss-ntlmssp is installed."
	exit 2
fi
if [ $b -ne 0 ]; then
	echo "CONFIRMED: a vcpkg-built krb5 does NOT see the host's NTLM mechanism."
	echo "A registry artifact would refuse every MECHANISM 'ntlm' ATTACH."
	[ $c -eq 0 ] && echo "Fixable at build time: --sysconfdir=/etc (arm C)."
	[ $d -eq 0 ] && echo "Fixable at run time:   GSS_MECH_CONFIG (single file)."
	exit 1
fi
echo "REFUTED: the vcpkg build registers NTLM too; the baked path is harmless."
