#include "xmla/gss_context.hpp"

#include "xmla/errors.hpp"

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <cctype>
#include <cstring>

namespace xmla {

namespace {

//! 1.3.6.1.4.1.311.2.2.10 - the NTLMSSP mechanism, as gss-ntlmssp registers it.
static gss_OID_desc kNtlmOidDesc = {10, const_cast<char *>("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")};
//! 1.2.840.113554.1.2.2 - the Kerberos v5 mechanism.
static gss_OID_desc kKrb5OidDesc = {9, const_cast<char *>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")};
//! 1.3.6.1.5.5.2 - SPNEGO.
static gss_OID_desc kSpnegoOidDesc = {6, const_cast<char *>("\x2b\x06\x01\x05\x05\x02")};

//! ADOMD's CalculateRequirements on the non-Schannel path with
//! ProtectionLevel.Privacy asks for mutual auth, replay and sequence detection,
//! confidentiality and integrity, and then refuses a context that did not grant
//! them. We ask for the same set and check the same way.
const OM_uint32 kRequestedFlags =
	GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;

//! Turn a GSS failure into one of our categories WITHOUT propagating the GSS
//! status text. gss_display_status routinely names the principal, the realm and
//! the target service, so quoting it would defeat constitution I in the one place
//! an operator is most likely to paste output.
[[noreturn]] void ThrowGss(const std::string &what) {
	throw AuthenticationError("the security layer rejected " + what);
}

Bytes ToBytes(const gss_buffer_desc &b) {
	const uint8_t *p = static_cast<const uint8_t *>(b.value);
	return Bytes(p, p + b.length);
}

// ---------------------------------------------------------------------------
// Provider 1: gss_wrap_iov. The detached split, directly.
// ---------------------------------------------------------------------------
//
// Available for Kerberos under MIT krb5. Measured against a real KDC across four
// AES enctypes: DATA stays at plaintext length, PADDING is zero, and the token
// is HEADER + TRAILER with sizes 60 / 64 / 72 bytes depending on the session key
// (research D5).
//
// The frame has ONE token field and the API wants TWO buffers, so on receive the
// split is recovered with gss_wrap_iov_length rather than from a table of
// per-enctype sizes - which is what keeps FR-017 ("neither size may be
// hardcoded") true for a mechanism we have not measured.
class IovSealProvider : public SealProvider {
public:
	IovSealProvider(gss_ctx_id_t ctx, size_t max_chunk) : ctx_(ctx), max_chunk_(max_chunk) {}

	Sealed Seal(const Bytes &plaintext) override {
		Bytes data = plaintext;
		gss_iov_buffer_desc iov[4];
		std::memset(iov, 0, sizeof(iov));
		iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
		iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		iov[1].buffer.value = data.data();
		iov[1].buffer.length = data.size();
		iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
		iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;

		OM_uint32 minor = 0;
		int conf_state = 0;
		const OM_uint32 major = gss_wrap_iov(&minor, ctx_, 1, GSS_C_QOP_DEFAULT, &conf_state, iov, 4);
		if (major != GSS_S_COMPLETE) {
			ThrowGss("a request it was asked to seal");
		}
		struct IovRelease {
			gss_iov_buffer_desc *iov;
			~IovRelease() {
				OM_uint32 m = 0;
				gss_release_iov_buffer(&m, iov, 4);
			}
		} release{iov};

		if (!conf_state) {
			// The context granted integrity but not confidentiality. Sending the
			// body in clear under a header that says "sealed" is worse than
			// failing: the operator would have no way to know.
			throw ProtocolError(
				"the security context did not encrypt the message; "
				"confidentiality was requested and not granted");
		}
		if (iov[2].buffer.length != 0) {
			throw ProtocolError("the negotiated mechanism padded the plaintext by " +
								std::to_string(iov[2].buffer.length) +
								" bytes, and this frame has no field to convey the unpadded length");
		}
		if (iov[1].buffer.length != plaintext.size()) {
			throw ProtocolError(
				"the negotiated mechanism did not preserve the plaintext length; "
				"the frame's dataSize cannot describe it");
		}

		Sealed out;
		out.ciphertext.assign(static_cast<uint8_t *>(iov[1].buffer.value),
							  static_cast<uint8_t *>(iov[1].buffer.value) + iov[1].buffer.length);
		// One wire token, two API buffers: HEADER then TRAILER, in that order.
		// Whether a Kerberos-speaking SSAS concatenates them this way or rotates
		// them (RFC 4121 RRC) is the open question in research D5. We can produce
		// either; we have no fixture that says which one it wants.
		out.token.reserve(iov[0].buffer.length + iov[3].buffer.length);
		out.token.insert(out.token.end(), static_cast<uint8_t *>(iov[0].buffer.value),
						 static_cast<uint8_t *>(iov[0].buffer.value) + iov[0].buffer.length);
		out.token.insert(out.token.end(), static_cast<uint8_t *>(iov[3].buffer.value),
						 static_cast<uint8_t *>(iov[3].buffer.value) + iov[3].buffer.length);
		return out;
	}

	Bytes Unseal(const Bytes &ciphertext, const Bytes &token) override {
		// Recover the header/trailer split WITHOUT a per-enctype table: ask the
		// mechanism what it would produce for a body of this length.
		gss_iov_buffer_desc query[4];
		std::memset(query, 0, sizeof(query));
		query[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
		query[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		query[1].buffer.length = ciphertext.size();
		query[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
		query[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
		OM_uint32 minor = 0;
		int conf_state = 0;
		if (gss_wrap_iov_length(&minor, ctx_, 1, GSS_C_QOP_DEFAULT, &conf_state, query, 4) != GSS_S_COMPLETE) {
			ThrowGss("a response it was asked to unseal");
		}
		const size_t header_len = query[0].buffer.length;
		const size_t trailer_len = query[3].buffer.length;
		if (header_len + trailer_len != token.size()) {
			// Not an internal error: this is what a token laid out differently
			// from ours looks like, and saying so points at the right question.
			throw ProtocolError("the response's token is " + std::to_string(token.size()) + " bytes but this context " +
								"produces " + std::to_string(header_len + trailer_len) +
								"; the peer's token layout differs from ours");
		}

		Bytes header(token.begin(), token.begin() + static_cast<long>(header_len));
		Bytes trailer(token.begin() + static_cast<long>(header_len), token.end());
		Bytes data = ciphertext;

		gss_iov_buffer_desc iov[4];
		std::memset(iov, 0, sizeof(iov));
		iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
		iov[0].buffer.value = header.data();
		iov[0].buffer.length = header.size();
		iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		iov[1].buffer.value = data.data();
		iov[1].buffer.length = data.size();
		iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
		iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
		iov[3].buffer.value = trailer.data();
		iov[3].buffer.length = trailer.size();

		if (gss_unwrap_iov(&minor, ctx_, &conf_state, nullptr, iov, 4) != GSS_S_COMPLETE) {
			ThrowGss("a response it was asked to unseal");
		}
		return Bytes(static_cast<uint8_t *>(iov[1].buffer.value),
					 static_cast<uint8_t *>(iov[1].buffer.value) + iov[1].buffer.length);
	}

	size_t MaxChunk() const override {
		return max_chunk_;
	}
	std::string Describe() const override {
		return "gss_wrap_iov (detached header/data/trailer)";
	}

private:
	gss_ctx_id_t ctx_;
	size_t max_chunk_;
};

// ---------------------------------------------------------------------------
// Provider 2: plain gss_wrap, split by length delta. NTLM only.
// ---------------------------------------------------------------------------
//
// gss-ntlmssp exports no IOV entry points, so gss_wrap_iov returns
// GSS_S_UNAVAILABLE (research D4). Plain gss_wrap under NTLM returns
// `token || ciphertext` with the ciphertext at plaintext length - the frame's
// two pieces, concatenated in the opposite order to the wire.
//
// The split point is DERIVED (`wrapped - plain`), never the constant 16, and the
// derivation is re-checked on every call rather than cached: FR-017 forbids
// hardcoding either size, and a mechanism whose overhead varied would otherwise
// be sliced silently wrong.
class WrapSplitSealProvider : public SealProvider {
public:
	WrapSplitSealProvider(gss_ctx_id_t ctx, size_t max_chunk) : ctx_(ctx), max_chunk_(max_chunk) {}

	Sealed Seal(const Bytes &plaintext) override {
		gss_buffer_desc in;
		in.value = const_cast<uint8_t *>(plaintext.data());
		in.length = plaintext.size();
		gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
		OM_uint32 minor = 0;
		int conf_state = 0;
		if (gss_wrap(&minor, ctx_, 1, GSS_C_QOP_DEFAULT, &in, &conf_state, &out) != GSS_S_COMPLETE) {
			ThrowGss("a request it was asked to seal");
		}
		struct Release {
			gss_buffer_desc *b;
			~Release() {
				OM_uint32 m = 0;
				gss_release_buffer(&m, b);
			}
		} release{&out};

		if (!conf_state) {
			throw ProtocolError(
				"the security context did not encrypt the message; "
				"confidentiality was requested and not granted");
		}
		if (out.length < plaintext.size()) {
			throw ProtocolError(
				"the wrapped message is shorter than its plaintext; "
				"this mechanism's token cannot be split by length");
		}
		const size_t token_len = out.length - plaintext.size();
		if (token_len == 0) {
			throw ProtocolError(
				"the negotiated mechanism produced no detachable token; "
				"the frame requires one");
		}
		const uint8_t *p = static_cast<const uint8_t *>(out.value);
		Sealed sealed;
		sealed.token.assign(p, p + token_len);
		sealed.ciphertext.assign(p + token_len, p + out.length);
		return sealed;
	}

	Bytes Unseal(const Bytes &ciphertext, const Bytes &token) override {
		// Rejoin in GSS order - token first - which is the inverse of the wire.
		Bytes joined;
		joined.reserve(token.size() + ciphertext.size());
		joined.insert(joined.end(), token.begin(), token.end());
		joined.insert(joined.end(), ciphertext.begin(), ciphertext.end());

		gss_buffer_desc in;
		in.value = joined.data();
		in.length = joined.size();
		gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
		OM_uint32 minor = 0;
		int conf_state = 0;
		// NOTE the parameter order: gss_unwrap takes the OUTPUT buffer BEFORE
		// conf_state, the reverse of gss_wrap. Getting it backwards compiles with
		// a warning and returns GSS_S_COMPLETE with zero bytes of plaintext,
		// which reads as a decryption failure rather than as a call-site bug.
		if (gss_unwrap(&minor, ctx_, &in, &out, &conf_state, nullptr) != GSS_S_COMPLETE) {
			ThrowGss("a response it was asked to unseal");
		}
		struct Release {
			gss_buffer_desc *b;
			~Release() {
				OM_uint32 m = 0;
				gss_release_buffer(&m, b);
			}
		} release{&out};
		return ToBytes(out);
	}

	size_t MaxChunk() const override {
		return max_chunk_;
	}
	std::string Describe() const override {
		return "gss_wrap with a derived token split";
	}

private:
	gss_ctx_id_t ctx_;
	size_t max_chunk_;
};

// ---------------------------------------------------------------------------
// The context itself
// ---------------------------------------------------------------------------

class RealGssContext : public GssContext {
public:
	RealGssContext(gss_name_t target, gss_cred_id_t cred, gss_OID mech) : target_(target), cred_(cred), mech_(mech) {}

	~RealGssContext() override {
		OM_uint32 minor = 0;
		if (ctx_ != GSS_C_NO_CONTEXT) {
			gss_delete_sec_context(&minor, &ctx_, GSS_C_NO_BUFFER);
		}
		if (target_ != GSS_C_NO_NAME) {
			gss_release_name(&minor, &target_);
		}
		if (cred_ != GSS_C_NO_CREDENTIAL) {
			gss_release_cred(&minor, &cred_);
		}
	}

	Bytes Step(const Bytes &in_token) override {
		gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
		if (!in_token.empty()) {
			in.value = const_cast<uint8_t *>(in_token.data());
			in.length = in_token.size();
		}
		gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
		OM_uint32 minor = 0;
		OM_uint32 flags = 0;
		const OM_uint32 major = gss_init_sec_context(&minor, cred_, &ctx_, target_, mech_, kRequestedFlags, 0,
													 GSS_C_NO_CHANNEL_BINDINGS, &in, nullptr, &out, &flags, nullptr);
		if (GSS_ERROR(major)) {
			ThrowGss("the credential offered for this connection");
		}
		complete_ = (major == GSS_S_COMPLETE);
		granted_ = flags;
		struct Release {
			gss_buffer_desc *b;
			~Release() {
				OM_uint32 m = 0;
				gss_release_buffer(&m, b);
			}
		} release{&out};
		return ToBytes(out);
	}

	bool IsComplete() const override {
		return complete_;
	}

	std::unique_ptr<SealProvider> MakeSealProvider() override {
		if (!complete_) {
			throw AuthenticationError("the security context is not established");
		}
		// ADOMD refuses a context that did not grant what it asked for, and so do
		// we. Sealing with a context that granted no confidentiality would send
		// the body in clear under a header claiming otherwise.
		if ((granted_ & GSS_C_CONF_FLAG) == 0) {
			throw AuthenticationError("the security context did not grant confidentiality");
		}
		if ((granted_ & GSS_C_INTEG_FLAG) == 0) {
			throw AuthenticationError("the security context did not grant integrity");
		}

		// The chunk size the reference client uses is min(cbMaxToken, 65535).
		// gss_wrap_size_limit is the GSS equivalent question. Smaller chunks are
		// always valid, so a mechanism that will not answer falls back to a safe
		// value rather than failing.
		OM_uint32 minor = 0;
		OM_uint32 limit = 0;
		size_t chunk = kFallbackChunk;
		if (gss_wrap_size_limit(&minor, ctx_, 1, GSS_C_QOP_DEFAULT, kMaxFrame, &limit) == GSS_S_COMPLETE && limit > 0) {
			chunk = limit < kMaxFrame ? limit : kMaxFrame;
		}

		// CAPABILITY PROBE, not a mechanism-name switch. gss_wrap_iov is asked
		// for a zero-length body: cheap, and it fails the same way a real call
		// would if the mech has no IOV entry points.
		if (SupportsIov()) {
			return std::unique_ptr<SealProvider>(new IovSealProvider(ctx_, chunk));
		}
		return std::unique_ptr<SealProvider>(new WrapSplitSealProvider(ctx_, chunk));
	}

private:
	//! dataSize is a uint16, so this is the hard ceiling regardless of mechanism.
	static const OM_uint32 kMaxFrame = 65535;
	//! The reference client's NTLM chunk size, used when the mechanism declines
	//! to state a limit. Smaller chunks are always valid, just more frames.
	static const size_t kFallbackChunk = 2888;

	bool SupportsIov() {
		gss_iov_buffer_desc iov[4];
		std::memset(iov, 0, sizeof(iov));
		iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
		iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		iov[1].buffer.length = 1;
		iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
		iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
		OM_uint32 minor = 0;
		int conf = 0;
		return gss_wrap_iov_length(&minor, ctx_, 1, GSS_C_QOP_DEFAULT, &conf, iov, 4) == GSS_S_COMPLETE;
	}

	gss_ctx_id_t ctx_ = GSS_C_NO_CONTEXT;
	gss_name_t target_ = GSS_C_NO_NAME;
	gss_cred_id_t cred_ = GSS_C_NO_CREDENTIAL;
	gss_OID mech_ = GSS_C_NO_OID;
	bool complete_ = false;
	OM_uint32 granted_ = 0;
};

}  // namespace

std::string Credential::Target(const std::string &host, uint16_t port) const {
	if (!spn_override.empty()) {
		return spn_override;
	}
	if (!instance.empty()) {
		return service + "/" + host + ":" + instance;
	}
	if (use_port) {
		return service + "/" + host + ":" + std::to_string(port);
	}
	return service + "/" + host;
}

std::unique_ptr<GssContext> GssContext::Create(const Credential &credential, const std::string &host, uint16_t port,
											   const std::string &password) {
	// ASCII-only fold. ::tolower follows LC_CTYPE, and "NEGOTIATE" contains an
	// I: under tr_TR.UTF-8 it would not fold to "negotiate", so the mechanism
	// would be REJECTED as unknown on a machine whose only fault is its locale.
	std::string mech = credential.mechanism;
	for (auto &c : mech) {
		c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
	}
	gss_OID mech_oid;
	if (mech == "ntlm") {
		mech_oid = &kNtlmOidDesc;
	} else if (mech == "kerberos") {
		mech_oid = &kKrb5OidDesc;
	} else if (mech == "negotiate") {
		mech_oid = &kSpnegoOidDesc;
	} else {
		// Reject rather than coerce. A typo silently becoming NTLM authenticates
		// with a mechanism the caller did not ask for.
		throw AuthenticationError("unknown mechanism '" + credential.mechanism +
								  "'; expected kerberos, negotiate or ntlm");
	}

	// BOTH halves come from Target(), not just the host: a full spn override
	// names its own service class, and taking only the host from it would
	// silently discard the very thing a site set it for.
	const std::string spn = credential.Target(host, port);
	const size_t slash = spn.find('/');
	if (slash == std::string::npos || slash == 0 || slash + 1 >= spn.size()) {
		throw AuthenticationError("spn must be of the form <service>/<host>");
	}
	// GSSAPI's hostbased-service form is service@host, not service/host.
	const std::string hostbased = spn.substr(0, slash) + "@" + spn.substr(slash + 1);

	OM_uint32 minor = 0;
	gss_buffer_desc name_buf;
	name_buf.value = const_cast<char *>(hostbased.c_str());
	name_buf.length = hostbased.size();
	gss_name_t target = GSS_C_NO_NAME;
	if (gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &target) != GSS_S_COMPLETE) {
		throw AuthenticationError("the target service name could not be parsed");
	}

	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
	if (!credential.principal.empty()) {
		gss_buffer_desc user_buf;
		user_buf.value = const_cast<char *>(credential.principal.c_str());
		user_buf.length = credential.principal.size();
		gss_name_t user_name = GSS_C_NO_NAME;
		if (gss_import_name(&minor, &user_buf, GSS_C_NT_USER_NAME, &user_name) != GSS_S_COMPLETE) {
			gss_release_name(&minor, &target);
			throw AuthenticationError("the principal could not be parsed");
		}
		gss_OID_set_desc mech_set = {1, mech_oid};
		OM_uint32 major;
		if (!password.empty()) {
			gss_buffer_desc pw;
			pw.value = const_cast<char *>(password.c_str());
			pw.length = password.size();
			major = gss_acquire_cred_with_password(&minor, user_name, &pw, GSS_C_INDEFINITE, &mech_set, GSS_C_INITIATE,
												   &cred, nullptr, nullptr);
		} else {
			major = gss_acquire_cred(&minor, user_name, GSS_C_INDEFINITE, &mech_set, GSS_C_INITIATE, &cred, nullptr,
									 nullptr);
		}
		gss_release_name(&minor, &user_name);
		if (major != GSS_S_COMPLETE) {
			gss_release_name(&minor, &target);
			// No GSS text: it names the principal and realm.
			throw AuthenticationError("no usable credential for the requested mechanism");
		}
	}
	// An empty principal means the ambient identity: GSS_C_NO_CREDENTIAL, which
	// draws on the ticket cache.

	return std::unique_ptr<GssContext>(new RealGssContext(target, cred, mech_oid));
}

}  // namespace xmla
