/* gss_wrap_iov is unavailable under gss-ntlmssp (verified: the plugin exports no
 * IOV entry points). So: does plain gss_wrap give a layout the SSAS frame can be
 * built from?
 *
 * The frame needs  ciphertext-at-plaintext-length  and  a detached token.
 * NTLM's GSS_Wrap token is documented as signature||sealed-data, so the split
 * should be at (wrapped_len - plaintext_len) with no rotation and no padding.
 * Do NOT hardcode 16: derive it, and prove it holds across sizes and across a
 * sequence of wraps (RC4 is a stream cipher, so keystream continuity matters).
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
	fprintf(stderr, "FAIL %s: major=0x%08x\n", what, maj);
	gss_display_status(&m, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &msg);
	fprintf(stderr, "  %.*s\n", (int)msg.length, (char *)msg.value);
	exit(1);
}

static void establish(gss_ctx_id_t *cctx, gss_ctx_id_t *sctx) {
	OM_uint32 maj, min;
	gss_OID_set_desc mechs = {1, ntlm_oid};
	gss_buffer_desc nb;
	nb.value = getenv("NTLM_PRINCIPAL");
	nb.length = strlen((char *)nb.value);
	gss_name_t cname = GSS_C_NO_NAME;
	gss_import_name(&min, &nb, GSS_C_NT_USER_NAME, &cname);
	gss_cred_id_t ccred = GSS_C_NO_CREDENTIAL, scred = GSS_C_NO_CREDENTIAL;
	maj = gss_acquire_cred(&min, cname, 0, &mechs, GSS_C_INITIATE, &ccred, NULL, NULL);
	if (maj) bail("acquire initiate", maj, min);
	maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, &mechs, GSS_C_ACCEPT, &scred, NULL, NULL);
	if (maj) bail("acquire accept", maj, min);
	gss_buffer_desc tb;
	tb.value = (void *)"MSOLAPSvc.3@ssas.example.com";
	tb.length = strlen((char *)tb.value);
	gss_name_t target = GSS_C_NO_NAME;
	gss_import_name(&min, &tb, GSS_C_NT_HOSTBASED_SERVICE, &target);
	OM_uint32 want = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER, in = GSS_C_EMPTY_BUFFER;
	OM_uint32 cf = 0, sf = 0;
	for (int i = 0; i < 8; i++) {
		maj = gss_init_sec_context(&min, ccred, cctx, target, ntlm_oid, want, 0,
		                           GSS_C_NO_CHANNEL_BINDINGS, &in, NULL, &out, &cf, NULL);
		if (GSS_ERROR(maj)) bail("init", maj, min);
		if (!out.length) break;
		gss_buffer_desc sout = GSS_C_EMPTY_BUFFER;
		OM_uint32 amaj = gss_accept_sec_context(&min, sctx, scred, &out, GSS_C_NO_CHANNEL_BINDINGS,
		                                        NULL, NULL, &sout, &sf, NULL, NULL);
		if (GSS_ERROR(amaj)) bail("accept", amaj, min);
		in = sout;
		if (maj == GSS_S_COMPLETE && amaj == GSS_S_COMPLETE) break;
	}
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	OM_uint32 maj, min;
	gss_ctx_id_t cctx = GSS_C_NO_CONTEXT, sctx = GSS_C_NO_CONTEXT;
	establish(&cctx, &sctx);
	printf("context established\n\n");

	/* what does the mech say the overhead is? */
	OM_uint32 limit = 0;
	maj = gss_wrap_size_limit(&min, cctx, 1, GSS_C_QOP_DEFAULT, 65535, &limit);
	printf("gss_wrap_size_limit(65535) = %u  (overhead %u)\n\n", limit, 65535 - limit);

	size_t sizes[] = {3, 1, 60, 563, 2888, 4096};
	int ok = 1;
	for (unsigned i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		size_t plen = sizes[i];
		char *plain = malloc(plen);
		for (size_t j = 0; j < plen; j++) plain[j] = (char)('A' + (j % 26));
		gss_buffer_desc in = {plen, plain}, out = GSS_C_EMPTY_BUFFER;
		int conf = 0;
		maj = gss_wrap(&min, cctx, 1, GSS_C_QOP_DEFAULT, &in, &conf, &out);
		if (maj) bail("gss_wrap", maj, min);
		size_t overhead = out.length - plen;
		/* Same reasoning as the Kerberos probe: at 1 byte this is a 1-in-256 coin
		 * flip rather than a measurement, so it is asserted from 3 bytes up while
		 * conf above carries the deterministic answer at every size. */
		/* conf is gss_wrap's own conf_state — deterministic, size-independent,
		 * and the actual evidence of confidentiality. */
		if (!conf) {
			printf("*** conf_state=0: the mechanism reports it did NOT encrypt\n");
			ok = 0;
		}
		int ct_checked = (plen >= 3);
		int tail_is_ct = !ct_checked || memcmp((char *)out.value + overhead, plain, plen) != 0;
		printf("plain=%-5zu wrapped=%-5zu overhead=%-3zu conf=%d  tail!=plain:%s  head: %02x %02x %02x %02x\n",
		       plen, (size_t)out.length, overhead, conf, ct_checked ? (tail_is_ct ? "yes" : "NO") : "n/a",
		       ((unsigned char *)out.value)[0], ((unsigned char *)out.value)[1],
		       ((unsigned char *)out.value)[2], ((unsigned char *)out.value)[3]);
		if (overhead != 16 || !tail_is_ct) ok = 0;

		/* round-trip through the server context, rebuilt in FRAME order:
		   ciphertext first, token second -> must be reassembled token-first */
		size_t tlen = overhead;
		char *frame = malloc(4 + plen + tlen);
		frame[0] = (char)(plen & 0xff); frame[1] = (char)((plen >> 8) & 0xff);
		frame[2] = (char)(tlen & 0xff); frame[3] = (char)((tlen >> 8) & 0xff);
		memcpy(frame + 4, (char *)out.value + tlen, plen);   /* ciphertext */
		memcpy(frame + 4 + plen, out.value, tlen);           /* token      */
		/* now undo it exactly as the reader will */
		size_t rdata = (unsigned char)frame[0] | ((unsigned char)frame[1] << 8);
		size_t rtok = (unsigned char)frame[2] | ((unsigned char)frame[3] << 8);
		char *rejoin = malloc(rdata + rtok);
		memcpy(rejoin, frame + 4 + rdata, rtok);
		memcpy(rejoin + rtok, frame + 4, rdata);
		gss_buffer_desc win = {rdata + rtok, rejoin}, wout = GSS_C_EMPTY_BUFFER;
		maj = gss_unwrap(&min, sctx, &win, &wout, &conf, NULL);
		if (maj) { printf("   *** unwrap FAILED 0x%08x\n", maj); ok = 0; }
		else if (wout.length != plen || memcmp(wout.value, plain, plen)) {
			printf("   *** round-trip MISMATCH: recovered %zu bytes, wanted %zu\n", (size_t)wout.length, plen);
			printf("       got : "); for (size_t k = 0; k < wout.length && k < 24; k++) printf("%02x ", ((unsigned char*)wout.value)[k]); printf("\n");
			printf("       want: "); for (size_t k = 0; k < plen && k < 24; k++) printf("%02x ", (unsigned char)plain[k]); printf("\n");
			ok = 0; }
		else printf("   frame round-trip OK (%zu bytes recovered)\n", (size_t)wout.length);
		free(plain); free(frame); free(rejoin);
	}
	printf("\nVERDICT: %s\n", ok ? "plain gss_wrap yields token(16)||ciphertext(plaintext-length); the frame is buildable for NTLM"
	                             : "*** the split does NOT hold ***");
	return ok ? 0 : 1;
}
