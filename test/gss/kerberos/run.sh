#!/bin/bash
# MIT KDC in one container. Measures what gss_wrap_iov does per SESSION-KEY
# enctype -- the key the wrap actually uses.
#
# Two traps this script exists to avoid, both of which produced a confident
# wrong answer on the way here:
#   1. dns_canonicalize_hostname collapses several test hostnames on one
#      loopback address to the FIRST /etc/hosts name, so every run silently
#      uses the same principal.
#   2. Varying the SERVICE KEY etype varies the TICKET etype, not the session
#      key. The session key comes from the client's default_tgs_enctypes.
#      Restricting permitted_enctypes instead breaks the acceptor's own keytab
#      read, which reports as "cannot decrypt ticket" and looks protocol-shaped.
set -euo pipefail
REALM=EXAMPLE.COM
HOST=ssas.example.com
ETYPES="aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128"

write_conf() {   # $1 = session-key etype to request, or "" for the default set
    local restrict="$1"
    {
        echo "[libdefaults]"
        echo "    default_realm = ${REALM}"
        echo "    dns_lookup_realm = false"
        echo "    dns_lookup_kdc = false"
        echo "    rdns = false"
        echo "    dns_canonicalize_hostname = false"
        # permitted_enctypes stays WIDE: it governs what the acceptor may read
        # from its keytab as well as what the client accepts.
        echo "    permitted_enctypes = ${ETYPES}"
        [ -n "${restrict}" ] && echo "    default_tkt_enctypes = ${restrict}"
        [ -n "${restrict}" ] && echo "    default_tgs_enctypes = ${restrict}"
        echo "[realms]"
        echo "    ${REALM} = {"
        echo "        kdc = localhost:88"
        echo "        admin_server = localhost:749"
        echo "    }"
        echo "[domain_realm]"
        echo "    .example.com = ${REALM}"
        echo "    example.com = ${REALM}"
    } > /etc/krb5.conf
}

mkdir -p /var/lib/krb5kdc /var/log
cat > /etc/krb5kdc/kdc.conf <<CONF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    ${REALM} = {
        database_name = /var/lib/krb5kdc/principal
        key_stash_file = /var/lib/krb5kdc/.k5.${REALM}
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal
    }
CONF
write_conf ""
echo "127.0.0.1 ${HOST}" >> /etc/hosts
kdb5_util create -s -P masterpw -r ${REALM} >/dev/null
echo '*/admin *' > /etc/krb5kdc/kadm5.acl
kadmin.local -q "addprinc -pw testpass testuser@${REALM}" >/dev/null 2>&1
# One service principal holding a key of EVERY etype, so the ticket can always
# be issued and decrypted and the only thing varying per run is the session key.
kadmin.local -q "addprinc -randkey MSOLAPSvc.3/${HOST}@${REALM}" >/dev/null 2>&1
kadmin.local -q "ktadd -k /etc/krb5.keytab MSOLAPSvc.3/${HOST}@${REALM}" >/dev/null 2>&1
# The port-suffixed shape ADOMD's DsMakeSpn emits, registered alongside the
# portless hostbased form GSSAPI builds.
kadmin.local -q "addprinc -randkey MSOLAPSvc.3/${HOST}:2383@${REALM}" >/dev/null 2>&1
kadmin.local -q "ktadd -k /etc/krb5.keytab MSOLAPSvc.3/${HOST}:2383@${REALM}" >/dev/null 2>&1

krb5kdc
for _ in $(seq 1 25); do echo 'testpass' | kinit testuser@${REALM} >/dev/null 2>&1 && break; sleep 0.2; done
klist -s || { echo "FATAL: KDC did not come up; every result below would be meaningless" >&2; exit 1; }
echo "KDC up. keytab holds:"; klist -k /etc/krb5.keytab | sed 's/^/  /'
echo

for e in ${ETYPES}; do
    echo "================================================================"
    echo "requested session-key etype: ${e}"
    echo "================================================================"
    write_conf "${e}"
    kdestroy -A 2>/dev/null || true
    if ! echo 'testpass' | kinit testuser@${REALM} >/dev/null 2>&1; then
        echo "  the KDC refused a TGT under ${e}; no result for this etype"; echo; continue
    fi
    /probe "MSOLAPSvc.3@${HOST}" || echo "  probe exited non-zero"
    # Report the etype ACTUALLY used, not the one asked for.
    skey=$(klist -e | grep -A1 "MSOLAPSvc.3/${HOST}@" | grep -o 'Etype (skey, tkt): [^,]*' | sed 's/.*: //')
    echo "  session key actually used: ${skey:-UNKNOWN}"
    # The literal word MISMATCH is what CI greps for; keep them in step.
    [ "${skey}" = "${e}" ] || echo "  *** MISMATCH: asked for ${e}, got ${skey} -- the row above measures ${skey}"
    echo
done
