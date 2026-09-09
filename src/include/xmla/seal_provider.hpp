//===----------------------------------------------------------------------===//
// How a payload becomes (ciphertext, token) for the SSAS sealed frame.
//
// The frame wants the ciphertext at PLAINTEXT LENGTH and the token DETACHED:
//
//     uint16 dataSize | uint16 tokenSize | ciphertext | token
//
// SSPI hands ADOMD exactly that as a SECBUFFER_DATA / SECBUFFER_TOKEN pair.
// GSS-API has two ways to produce it and NEITHER works for both mechanisms:
//
//   * gss_wrap_iov with HEADER/DATA/PADDING/TRAILER gives the detached split
//     directly. Available for Kerberos under MIT krb5. NOT available for NTLM:
//     gss-ntlmssp 1.2.0 exports no IOV entry points at all, so the mechglue
//     returns GSS_S_UNAVAILABLE and no plugin version bump is implied
//     (research D4).
//
//   * plain gss_wrap returns, for NTLM only, `token || ciphertext` with the
//     ciphertext already at plaintext length - the frame's two pieces, just
//     concatenated in the opposite order to the wire (research D4). This does
//     NOT generalise: a Kerberos GSS_Wrap token encrypts the plaintext inside
//     itself under RRC rotation, with no fixed offset to slice at.
//
// So the provider is chosen by CAPABILITY PROBE, never by mechanism name. A
// future gss-ntlmssp that gains IOV support is then picked up without a code
// change, and a mechanism we have not met is refused rather than mis-sliced.
//===----------------------------------------------------------------------===//
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace xmla {

using Bytes = std::vector<uint8_t>;

struct Sealed {
	Bytes ciphertext;  //!< exactly plaintext length
	Bytes token;	   //!< detached; length varies by mechanism and, for Kerberos, by enctype
};

//! Seals and unseals one message body with an established security context.
class SealProvider {
public:
	virtual ~SealProvider() = default;

	//! Wrap one payload. Throws ProtocolError if the mechanism pads: the frame
	//! has two length fields and NEITHER carries the unpadded plaintext length,
	//! so padding bytes would sit inside dataSize with nothing to strip them by.
	//! Measured zero for NTLM and for every AES Kerberos enctype (research D5),
	//! so this is a guard against a mechanism we have not met, not an expected
	//! path.
	virtual Sealed Seal(const Bytes &plaintext) = 0;

	//! Unwrap one frame back to plaintext.
	virtual Bytes Unseal(const Bytes &ciphertext, const Bytes &token) = 0;

	//! The reference client's data chunk size for this mechanism. Not a protocol
	//! limit - the limit is 65535, since dataSize is a uint16 - but matching it
	//! keeps our frames the same shape as a real client's.
	virtual size_t MaxChunk() const = 0;

	//! For diagnostics only. Never contains a principal, realm or token.
	virtual std::string Describe() const = 0;
};

}  // namespace xmla
