//===----------------------------------------------------------------------===//
// Seal providers shaped like the real mechanisms, without a security library.
//
// The sizes are not invented. They are what the probes in test/gss/ measured
// (research D4, D5):
//
//   NTLM                        token 16 bytes, no padding
//   Kerberos aes256-sha1-96     token 60 bytes (header 32 + trailer 28)
//   Kerberos aes128-sha256-128  token 64 bytes
//   Kerberos aes256-sha384-192  token 72 bytes
//
// Using more than one of those is the point: the reference implementation's
// Kerberos-shaped test used a single 60-byte token, which happens to be right for
// exactly one enctype. A layer that hardcodes 16 - or 60 - passes that test and
// fails on a real AES session.
//
// The "cipher" is a keystream XOR, not for secrecy but because it is
// length-preserving and order-sensitive, which is what the frame relies on.
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/errors.hpp"
#include "xmla/seal_provider.hpp"

#include <string>

namespace xmla {

class FakeSealProvider : public SealProvider {
public:
	FakeSealProvider(size_t token_len, size_t max_chunk, size_t padding = 0)
		: token_len_(token_len), max_chunk_(max_chunk), padding_(padding) {}

	Sealed Seal(const Bytes &plaintext) override {
		if (padding_ != 0) {
			throw ProtocolError("the negotiated mechanism padded the plaintext by " + std::to_string(padding_) +
								" bytes, and this frame has no field to convey the unpadded length");
		}
		Sealed out;
		out.ciphertext = Xor(plaintext, seq_);
		out.token.assign(token_len_, 0);
		if (token_len_ >= 4) {
			// A recognisable token, and one that changes per frame, so a test can
			// tell frames apart and catch a reader that reuses one.
			out.token[0] = 0x01;
			out.token[3] = static_cast<uint8_t>(seq_ & 0xFF);
		}
		seq_++;
		return out;
	}

	Bytes Unseal(const Bytes &ciphertext, const Bytes &token) override {
		if (token.size() != token_len_) {
			throw ProtocolError("token length " + std::to_string(token.size()) + " does not match this context's " +
								std::to_string(token_len_));
		}
		const uint32_t seq = token.size() >= 4 ? token[3] : 0;
		return Xor(ciphertext, seq);
	}

	size_t MaxChunk() const override {
		return max_chunk_;
	}
	std::string Describe() const override {
		return "fake provider, token " + std::to_string(token_len_);
	}

	//! How many frames this provider has sealed. Lets a test assert chunking
	//! happened rather than inferring it from a length.
	uint32_t frames_sealed() const {
		return seq_;
	}

private:
	static Bytes Xor(const Bytes &in, uint32_t seq) {
		Bytes out(in.size());
		for (size_t i = 0; i < in.size(); i++) {
			out[i] = static_cast<uint8_t>(in[i] ^ (0xA5 + seq + (i & 0x1F)));
		}
		return out;
	}

	size_t token_len_;
	size_t max_chunk_;
	size_t padding_;
	uint32_t seq_ = 0;
};

//! A provider that does not preserve the plaintext length. The frame's dataSize
//! cannot describe such a mechanism, so sealing must refuse it.
class LengthChangingProvider : public SealProvider {
public:
	Sealed Seal(const Bytes &plaintext) override {
		Sealed out;
		out.ciphertext = plaintext;
		out.ciphertext.push_back(0x00);
		out.token.assign(16, 0);
		return out;
	}
	Bytes Unseal(const Bytes &ciphertext, const Bytes &) override {
		return ciphertext;
	}
	size_t MaxChunk() const override {
		return 2888;
	}
	std::string Describe() const override {
		return "length-changing";
	}
};

}  // namespace xmla
