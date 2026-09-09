/* Kerberos half of the sealing question.
 *
 * Settles, against a real KDC, the three things the reference implementation
 * had to leave UNVERIFIED:
 *   1. does gss_wrap_iov give the detached DATA/TOKEN split under MIT krb5?
 *   2. how big is the token (the frame's uint16 tokenSize) per etype?
 *   3. does gss_wrap_iov report NON-ZERO padding? The frame has no field for
 *      an unpadded length, so a padding mechanism cannot be expressed.
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show(const char *w, OM_uint32 maj, OM_uint32 min) {
	OM_uint32 m, c = 0;
	gss_buffer_desc b = GSS_C_EMPTY_BUFFER;
	gss_display_status(&m, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &c, &b);
	fprintf(stderr, "  %s: maj=0x%08x  %.*s\n", w, maj, (int)b.length, (char *)b.value);
	c = 0;
	gss_display_status(&m, min, GSS_C_MECH_CODE, (gss_OID)gss_mech_krb5, &c, &b);
	fprintf(stderr, "       mech: %.*s\n", (int)b.length, (char *)b.value);
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	OM_uint32 maj, min;
	const char *spn = argc > 1 ? argv[1] : "MSOLAPSvc.3@ssas.example.com";

	gss_buffer_desc tb;
	tb.value = (void *)spn;
	tb.length = strlen(spn);
	gss_name_t target = GSS_C_NO_NAME;
	maj = gss_import_name(&min, &tb, GSS_C_NT_HOSTBASED_SERVICE, &target);
	if (maj) { show("import_name", maj, min); return 1; }

	gss_cred_id_t scred = GSS_C_NO_CREDENTIAL;
	maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &scred, NULL, NULL);
	if (maj) { show("acquire(accept)", maj, min); return 1; }

	/* ADOMD's CalculateRequirements: mutual|replay|sequence|conf|integ */
	OM_uint32 want = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
	/* SSPI hands ADOMD ONE token buffer; MIT's default wrap_iov hands back two
	 * (HEADER before DATA, TRAILER after). GSS_C_DCE_STYLE is MIT's switch to
	 * the RRC-rotated single-buffer form SSPI uses. */
	const int dce = getenv("DCE_STYLE") && *getenv("DCE_STYLE") == '1';
	if (dce) { want |= GSS_C_DCE_STYLE; printf("[GSS_C_DCE_STYLE requested]\n"); }
	gss_ctx_id_t cx = GSS_C_NO_CONTEXT, sx = GSS_C_NO_CONTEXT;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER, in = GSS_C_EMPTY_BUFFER;
	OM_uint32 cf = 0, sf = 0;
	int legs = 0, client_done = 0, server_done = 0;
	/* Canonical GSS loop. With mutual auth the client is NOT finished when it
	 * emits the AP_REQ: it must consume the server's AP_REP, and calling
	 * init_sec_context again after it has returned COMPLETE is an error
	 * ("context is already fully established"), not a no-op. */
	while (!client_done) {
		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &cx, target, (gss_OID)gss_mech_krb5, want, 0,
		                           GSS_C_NO_CHANNEL_BINDINGS, &in, NULL, &out, &cf, NULL);
		if (GSS_ERROR(maj)) { show("init_sec_context", maj, min); return 1; }
		client_done = (maj == GSS_S_COMPLETE);
		if (in.value) { OM_uint32 m; gss_release_buffer(&m, &in); in = (gss_buffer_desc)GSS_C_EMPTY_BUFFER; }
		if (!out.length) break;
		legs++;
		printf("leg %d: client -> %-5zu bytes  (init %s)\n", legs, (size_t)out.length,
		       client_done ? "COMPLETE" : "CONTINUE");
		gss_buffer_desc so = GSS_C_EMPTY_BUFFER;
		OM_uint32 am = gss_accept_sec_context(&min, &sx, scred, &out, GSS_C_NO_CHANNEL_BINDINGS,
		                                      NULL, NULL, &so, &sf, NULL, NULL);
		if (GSS_ERROR(am)) { show("accept_sec_context", am, min); return 1; }
		server_done = (am == GSS_S_COMPLETE);
		{ OM_uint32 m; gss_release_buffer(&m, &out); out = (gss_buffer_desc)GSS_C_EMPTY_BUFFER; }
		printf("       server -> %-5zu bytes  (accept %s)\n", (size_t)so.length,
		       server_done ? "COMPLETE" : "CONTINUE");
		in = so;
		if (client_done && !in.length) break;
	}
	if (!server_done) { fprintf(stderr, "acceptor never completed\n"); return 1; }

	printf("\nhandshake complete in %d client legs. flags=0x%x conf=%d integ=%d seq=%d replay=%d mutual=%d\n",
	       legs, cf, !!(cf & GSS_C_CONF_FLAG), !!(cf & GSS_C_INTEG_FLAG), !!(cf & GSS_C_SEQUENCE_FLAG),
	       !!(cf & GSS_C_REPLAY_FLAG), !!(cf & GSS_C_MUTUAL_FLAG));

	/* which etype actually got negotiated */
	gss_buffer_set_t bset = GSS_C_NO_BUFFER_SET;
	gss_OID_desc sess_oid = {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04"}; /* GSS_KRB5_GET_SUBKEY / session key */
	maj = gss_inquire_sec_context_by_oid(&min, cx, &sess_oid, &bset);
	if (maj == GSS_S_COMPLETE && bset && bset->count > 0)
		printf("session key: %zu bytes\n", (size_t)bset->elements[0].length);

	printf("\n%-6s %-8s %-8s %-8s %-8s %-8s %s\n", "plain", "HEADER", "DATA", "PADDING", "TRAILER", "total", "verdict");
	size_t sizes[] = {3, 1, 60, 563, 2888, 4096, 65000};
	int pad_seen = 0, ok = 1;
	for (unsigned i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		size_t plen = sizes[i];
		char *data = malloc(plen);
		for (size_t j = 0; j < plen; j++) data[j] = (char)('A' + (j % 26));
		char *orig = malloc(plen);
		memcpy(orig, data, plen);

		gss_iov_buffer_desc iov[4];
		memset(iov, 0, sizeof(iov));
		iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
		iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		iov[1].buffer.value = data;
		iov[1].buffer.length = plen;
		iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
		iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
		int conf = 0;
		maj = gss_wrap_iov(&min, cx, 1, GSS_C_QOP_DEFAULT, &conf, iov, 4);
		if (maj) { show("gss_wrap_iov", maj, min); return 1; }

		size_t h = iov[0].buffer.length, d = iov[1].buffer.length, p = iov[2].buffer.length, t = iov[3].buffer.length;
		if (p) pad_seen = 1;
		int len_ok = (d == plen);
		/* "Did it encrypt?" is a byte-inequality test, and for a TINY payload that
		 * is a coin flip, not a measurement: with 1 byte the ciphertext coincides
		 * with the plaintext once in 256 runs. It duly did, in CI, and reported
		 * NOT-ENCRYPTED for aes128-cts-hmac-sha1-96 — an alarm about the
		 * mechanism caused entirely by the size of the sample.
		 *
		 * Only assert it from 8 bytes up, where a coincidence is 2^-64. The small
		 * sizes still assert length-preservation and the round-trip, which are
		 * deterministic and are what the frame actually depends on. */
		/* conf_state is the mechanism's OWN answer to "did you encrypt?", it is
		 * deterministic, and it does not care how big the payload is. It was
		 * being computed and thrown away while a byte-comparison stood in for
		 * it. Assert it at EVERY size; the byte comparison is then only a
		 * cross-check, and only where it is meaningful. */
		if (!conf) {
			printf("*** conf_state=0: the mechanism reports it did NOT encrypt\n");
			ok = 0;
		}
		/* 3 bytes is 2^-24 — comparable to the KDC container's own flake rate —
		 * so only the 1-byte row is genuinely a coin flip. Excluding more than
		 * that discards real measurement to buy nothing. */
		int enc_checked = (plen >= 3);
		int enc_ok = !enc_checked || memcmp(iov[1].buffer.value, orig, plen) != 0;
		if (!len_ok || !enc_ok) ok = 0;

		/* unwrap through the acceptor, reassembled the way the frame reader will */
		gss_iov_buffer_desc riov[4];
		memset(riov, 0, sizeof(riov));
		riov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;  riov[0].buffer = iov[0].buffer;
		riov[1].type = GSS_IOV_BUFFER_TYPE_DATA;    riov[1].buffer = iov[1].buffer;
		riov[2].type = GSS_IOV_BUFFER_TYPE_PADDING; riov[2].buffer = iov[2].buffer;
		riov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER; riov[3].buffer = iov[3].buffer;
		/* NOT into `conf`: that would overwrite the wrap's answer before it has
		 * been asserted, which is how it came to be unused in the first place. */
		int unwrap_conf = 0;
		OM_uint32 umaj = gss_unwrap_iov(&min, sx, &unwrap_conf, NULL, riov, 4);
		int rt = (umaj == GSS_S_COMPLETE && riov[1].buffer.length == plen && !memcmp(riov[1].buffer.value, orig, plen));
		if (!rt) ok = 0;

		printf("%-6zu %-8zu %-8zu %-8zu %-8zu %-8zu %s%s%s\n", plen, h, d, p, t, h + d + p + t,
		       len_ok ? "len-ok " : "LEN-CHANGED ",
		       enc_checked ? (enc_ok ? "enc-ok " : "NOT-ENCRYPTED ") : "enc-n/a ",
		       rt ? "rt-ok" : "RT-FAILED");
		free(data); free(orig);
	}

	{
		/* Can a RECEIVER derive the header/trailer split from dataSize alone,
		 * without a table of etype sizes? gss_wrap_iov_length answers that. */
		gss_iov_buffer_desc q[4];
		memset(q, 0, sizeof(q));
		q[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
		q[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		q[1].buffer.length = 563;
		q[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
		q[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
		int c2 = 0;
		OM_uint32 lm = gss_wrap_iov_length(&min, cx, 1, GSS_C_QOP_DEFAULT, &c2, q, 4);
		if (lm == GSS_S_COMPLETE)
			printf("gss_wrap_iov_length(data=563): header=%zu padding=%zu trailer=%zu  "
			       "-> a receiver CAN derive the split\n",
			       (size_t)q[0].buffer.length, (size_t)q[2].buffer.length, (size_t)q[3].buffer.length);
		else
			printf("gss_wrap_iov_length unavailable (0x%08x)\n", lm);
	}
	printf("\ntoken for the frame = HEADER + TRAILER (both detached from DATA)\n");
	printf("PADDING seen: %s\n", pad_seen ? "*** YES - the frame cannot express this ***" : "no (frame is expressible)");
	printf("VERDICT: %s\n", ok && !pad_seen ? "gss_wrap_iov gives the SSAS frame layout under Kerberos"
	                                        : "*** NOT usable as-is ***");
	return ok && !pad_seen ? 0 : 1;
}
