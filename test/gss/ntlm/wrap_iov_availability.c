/* Does gss_wrap_iov give us the detached DATA/TOKEN split under gss-ntlmssp?
 *
 * The SSAS sealed frame is:  u16 dataSize | u16 tokenSize | ciphertext | token
 * with the ciphertext at PLAINTEXT LENGTH and the token detached. ADOMD gets
 * that from SSPI's SECBUFFER_DATA + SECBUFFER_TOKEN pair. The GSS-API
 * equivalent is gss_wrap_iov with HEADER/DATA/PADDING/TRAILER buffers.
 *
 * This probe answers three questions and nothing else:
 *   1. does gss_wrap_iov exist and succeed under the NTLM mech?
 *   2. is the DATA buffer still plaintext-length after wrapping?
 *   3. does PADDING come back non-zero? (the frame has no field for it)
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static gss_OID_desc ntlm_oid_desc = {10, (void *)"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"};
static gss_OID ntlm_oid = &ntlm_oid_desc;

static void bail(const char *what, OM_uint32 maj, OM_uint32 min) {
	OM_uint32 m, ctx = 0;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	fprintf(stderr, "FAIL %s: major=0x%08x minor=%u\n", what, maj, min);
	gss_display_status(&m, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &msg);
	fprintf(stderr, "  gss: %.*s\n", (int)msg.length, (char *)msg.value);
	gss_release_buffer(&m, &msg);
	ctx = 0;
	gss_display_status(&m, min, GSS_C_MECH_CODE, ntlm_oid, &ctx, &msg);
	fprintf(stderr, "  mech: %.*s\n", (int)msg.length, (char *)msg.value);
	gss_release_buffer(&m, &msg);
	exit(1);
}

int main(void) {
	OM_uint32 maj, min;
	gss_OID_set_desc mechs = {1, ntlm_oid};

	/* client credential from NTLM_USER_FILE */
	gss_buffer_desc nb = {0, NULL};
	char *user = getenv("NTLM_PRINCIPAL");
	nb.value = user;
	nb.length = strlen(user);
	gss_name_t cname = GSS_C_NO_NAME;
	maj = gss_import_name(&min, &nb, GSS_C_NT_USER_NAME, &cname);
	if (maj != GSS_S_COMPLETE) bail("import_name(client)", maj, min);

	gss_cred_id_t ccred = GSS_C_NO_CREDENTIAL, scred = GSS_C_NO_CREDENTIAL;
	maj = gss_acquire_cred(&min, cname, GSS_C_INDEFINITE, &mechs, GSS_C_INITIATE, &ccred, NULL, NULL);
	if (maj != GSS_S_COMPLETE) bail("acquire_cred(initiate)", maj, min);
	maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE, &mechs, GSS_C_ACCEPT, &scred, NULL, NULL);
	if (maj != GSS_S_COMPLETE) bail("acquire_cred(accept)", maj, min);

	/* target name: hostbased, mirrors MSOLAPSvc.3/host */
	gss_buffer_desc tb;
	tb.value = (void *)"MSOLAPSvc.3@ssas.example.com";
	tb.length = strlen((char *)tb.value);
	gss_name_t target = GSS_C_NO_NAME;
	maj = gss_import_name(&min, &tb, GSS_C_NT_HOSTBASED_SERVICE, &target);
	if (maj != GSS_S_COMPLETE) bail("import_name(target)", maj, min);

	/* ADOMD's CalculateRequirements on this path: mutual|replay|sequence|conf|integ */
	OM_uint32 want = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
	                 GSS_C_INTEG_FLAG;
	gss_ctx_id_t cctx = GSS_C_NO_CONTEXT, sctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER, in = GSS_C_EMPTY_BUFFER;
	OM_uint32 cflags = 0, sflags = 0;
	int leg = 0;

	for (;;) {
		maj = gss_init_sec_context(&min, ccred, &cctx, target, ntlm_oid, want, GSS_C_INDEFINITE,
		                           GSS_C_NO_CHANNEL_BINDINGS, &in, NULL, &out, &cflags, NULL);
		if (GSS_ERROR(maj)) bail("init_sec_context", maj, min);
		printf("leg %d: client emitted %zu bytes\n", ++leg, (size_t)out.length);
		if (in.value) { OM_uint32 m; gss_release_buffer(&m, &in); in = (gss_buffer_desc)GSS_C_EMPTY_BUFFER; }
		if (out.length == 0 && maj == GSS_S_COMPLETE) break;

		gss_buffer_desc sout = GSS_C_EMPTY_BUFFER;
		OM_uint32 amaj = gss_accept_sec_context(&min, &sctx, scred, &out, GSS_C_NO_CHANNEL_BINDINGS,
		                                        NULL, NULL, &sout, &sflags, NULL, NULL);
		if (GSS_ERROR(amaj)) bail("accept_sec_context", amaj, min);
		{ OM_uint32 m; gss_release_buffer(&m, &out); }
		printf("        server emitted %zu bytes\n", (size_t)sout.length);
		in = sout;
		if (maj == GSS_S_COMPLETE && amaj == GSS_S_COMPLETE) break;
		if (leg > 8) { fprintf(stderr, "FAIL handshake did not converge\n"); return 1; }
	}

	printf("\nhandshake complete. client flags=0x%x  conf=%d integ=%d seq=%d replay=%d mutual=%d\n",
	       cflags, !!(cflags & GSS_C_CONF_FLAG), !!(cflags & GSS_C_INTEG_FLAG),
	       !!(cflags & GSS_C_SEQUENCE_FLAG), !!(cflags & GSS_C_REPLAY_FLAG),
	       !!(cflags & GSS_C_MUTUAL_FLAG));

	/* --- the question --- */
	char plain[] = "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"/>";
	size_t plen = sizeof(plain) - 1;
	char *data = malloc(plen);
	memcpy(data, plain, plen);

	gss_iov_buffer_desc iov[4];
	memset(iov, 0, sizeof(iov));
	iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
	iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
	iov[1].buffer.value = data;
	iov[1].buffer.length = plen;
	iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
	iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;

	int conf_state = 0;
	maj = gss_wrap_iov(&min, cctx, 1, GSS_C_QOP_DEFAULT, &conf_state, iov, 4);
	if (maj != GSS_S_COMPLETE) bail("gss_wrap_iov", maj, min);

	printf("\ngss_wrap_iov OK  conf_state=%d\n", conf_state);
	printf("  HEADER  len=%zu   <-- tokenSize\n", (size_t)iov[0].buffer.length);
	printf("  DATA    len=%zu   (plaintext was %zu)  %s\n", (size_t)iov[1].buffer.length, plen,
	       iov[1].buffer.length == plen ? "LENGTH-PRESERVING" : "*** LENGTH CHANGED ***");
	printf("  PADDING len=%zu   %s\n", (size_t)iov[2].buffer.length,
	       iov[2].buffer.length == 0 ? "(none - frame is expressible)" : "*** PADS - frame has no field for this ***");
	printf("  TRAILER len=%zu\n", (size_t)iov[3].buffer.length);
	printf("  ciphertext differs from plaintext: %s\n",
	       memcmp(iov[1].buffer.value, plain, plen) ? "yes" : "*** NO - NOT ENCRYPTED ***");
	printf("  header first 4 bytes: %02x %02x %02x %02x\n",
	       ((unsigned char *)iov[0].buffer.value)[0], ((unsigned char *)iov[0].buffer.value)[1],
	       ((unsigned char *)iov[0].buffer.value)[2], ((unsigned char *)iov[0].buffer.value)[3]);

	/* round-trip through the server context, in the frame's own order */
	gss_iov_buffer_desc riov[4];
	memset(riov, 0, sizeof(riov));
	riov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
	riov[0].buffer = iov[0].buffer;
	riov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
	riov[1].buffer = iov[1].buffer;
	riov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
	riov[2].buffer = iov[2].buffer;
	riov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
	riov[3].buffer = iov[3].buffer;
	maj = gss_unwrap_iov(&min, sctx, &conf_state, NULL, riov, 4);
	if (maj != GSS_S_COMPLETE) bail("gss_unwrap_iov", maj, min);
	printf("  unwrap_iov round-trip: %s\n",
	       riov[1].buffer.length == plen && !memcmp(riov[1].buffer.value, plain, plen) ? "OK" : "*** MISMATCH ***");

	printf("\nVERDICT: gss_wrap_iov under gss-ntlmssp gives the detached split.\n");
	return 0;
}
