/* Does a vcpkg-built krb5 register the system's NTLM mechanism?
 *
 * The community-extensions registry builds through vcpkg and has no system
 * krb5, so vcpkg.json declares the port and the registry links what it builds.
 * MIT krb5 bakes the path it consults for mechanism plugins at CONFIGURE time:
 * osconf.hin defines MECH_CONF as "@SYSCONFDIR/gss/mech", and vcpkg passes only
 * --prefix, leaving sysconfdir at ${prefix}/etc -- a directory inside the build
 * tree that does not exist on any user's machine. gss-ntlmssp installs its entry
 * in the HOST's /etc/gss/mech.d, and mechglue/Makefile.in sets _GSS_STATIC_LINK,
 * so krb5 and SPNEGO are compiled in and NTLM can only arrive from that file.
 *
 * NTLM is the only auth path this project has verified end to end, and the
 * registry listing's own example uses MECHANISM 'ntlm', so the question is
 * whether a published build can do the thing it advertises.
 *
 * This probe answers one question: does gss_indicate_mechs report the NTLM OID,
 * and does gss_acquire_cred accept it? What matters is WHICH error comes back,
 * because from the outside they look alike:
 *
 *   GSS_S_BAD_MECH (0x00010000)  the mechanism does not exist at all
 *                                -- the failure this probe exists to catch
 *   anything else                the mechanism was found and the call failed on
 *                                its own terms. In this container that is
 *                                GSS_S_FAILURE (0x000d0000, routine error 13)
 *                                from gss-ntlmssp, which has no NTLM_USER_FILE
 *                                to read -- expected, and a PASS here.
 *
 * Note 0x000d0000 is GSS_S_FAILURE, not GSS_S_NO_CRED: the routine errors are
 * numbered in the order they appear in RFC 2744, so NO_CRED is 7 (0x00070000)
 * and FAILURE is 13. Getting that backwards makes a mechanism that is present
 * look like one that is missing, which is the whole question here.
 *
 * The distinction matters because src/gss_context.cpp suppresses GSS status
 * text under constitution I, so in production a missing mechanism and a wrong
 * password are reported identically.
 */
#include <gssapi/gssapi.h>
#include <stdio.h>
#include <string.h>

/* 1.3.6.1.4.1.311.2.2.10 -- gss-ntlmssp's gssntlmssp_v1 */
static gss_OID_desc ntlm_oid_desc = {10, (void *)"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"};
static gss_OID ntlm_oid = &ntlm_oid_desc;

static void print_oid(gss_OID o) {
	for (size_t i = 0; i < o->length; i++)
		printf("%02x", ((unsigned char *)o->elements)[i]);
}

int main(void) {
	OM_uint32 major, minor;
	gss_OID_set mechs = GSS_C_NO_OID_SET;
	int found = 0;

	major = gss_indicate_mechs(&minor, &mechs);
	if (GSS_ERROR(major)) {
		printf("FAIL gss_indicate_mechs: major=0x%08x\n", (unsigned)major);
		return 2;
	}

	printf("  mechanisms reported: %d\n", (int)mechs->count);
	for (size_t i = 0; i < mechs->count; i++) {
		gss_OID o = &mechs->elements[i];
		printf("    ");
		print_oid(o);
		if (o->length == ntlm_oid->length &&
		    memcmp(o->elements, ntlm_oid->elements, o->length) == 0) {
			printf("   <-- NTLM (gss-ntlmssp)");
			found = 1;
		}
		printf("\n");
	}
	gss_release_oid_set(&minor, &mechs);

	/* The mech list is what the mechglue loaded. This is what an
	   ATTACH ... MECHANISM 'ntlm' actually depends on, so ask it directly:
	   BAD_MECH here means the plugin was never registered, whatever the list
	   above happened to say. */
	gss_OID_set_desc want = {1, ntlm_oid};
	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
	OM_uint32 amaj, amin;
	amaj = gss_acquire_cred(&amin, GSS_C_NO_NAME, 0, &want, GSS_C_INITIATE,
	                        &cred, NULL, NULL);
	if (cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&amin, &cred);

	const char *verdict;
	if (GSS_ROUTINE_ERROR(amaj) == GSS_S_BAD_MECH) {
		verdict = "BAD_MECH -- the mechanism does not exist";
		found = 0;
	} else if (GSS_ROUTINE_ERROR(amaj) == GSS_S_NO_CRED) {
		verdict = "NO_CRED -- mechanism present, no credential (expected)";
	} else if (GSS_ROUTINE_ERROR(amaj) == GSS_S_FAILURE) {
		verdict = "FAILURE -- mechanism present, it declined (expected here)";
	} else if (GSS_ERROR(amaj)) {
		verdict = "mechanism present, unexpected error";
	} else {
		verdict = "ok";
	}
	printf("  gss_acquire_cred(NTLM): major=0x%08x  %s\n", (unsigned)amaj, verdict);
	if (GSS_ERROR(amaj) && GSS_ROUTINE_ERROR(amaj) != GSS_S_BAD_MECH) {
		/* Safe to display here and nowhere else: this probe never touches a
		   real account, so constitution I's rule against surfacing GSS status
		   text does not apply. It is what tells a reader that the mechanism
		   really did run. */
		OM_uint32 m, ctx = 0;
		gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
		gss_display_status(&m, amaj, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &msg);
		printf("    gss: %.*s\n", (int)msg.length, (char *)msg.value);
		gss_release_buffer(&m, &msg);
	}
	printf("  RESULT: NTLM %s\n", found ? "REGISTERED" : "ABSENT");
	return found ? 0 : 1;
}
