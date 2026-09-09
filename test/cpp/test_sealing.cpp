#include "fake_provider.hpp"
#include "harness.hpp"
#include "xmla/errors.hpp"
#include "xmla/sealing.hpp"

#include <string>

using namespace xmla;

static Bytes Str(const std::string &s) {
	return Bytes(s.begin(), s.end());
}

//! Every measured token size, so nothing can quietly assume one of them.
static const size_t kTokenSizes[] = {16, 60, 64, 72};

TEST_CASE("the frame is dataSize, tokenSize, ciphertext, token - in that order") {
	FakeSealProvider p(16, 2888);
	const Bytes frame = sealing::SealFrame(p, Str("abc"));
	// Little-endian sizes, unlike the big-endian DIME header below it.
	REQUIRE_EQ(frame[0], 3);
	REQUIRE_EQ(frame[1], 0);
	REQUIRE_EQ(frame[2], 16);
	REQUIRE_EQ(frame[3], 0);
	REQUIRE_EQ(frame.size(), 4u + 3u + 16u);
	// CIPHERTEXT first. The token is recognisable, so a reversed frame is
	// detectable rather than merely wrong.
	REQUIRE(frame[4] != 0x01);
	REQUIRE_EQ(frame[4 + 3], 0x01);
}

TEST_CASE("a message round-trips at every measured token size") {
	// The reference implementation's Kerberos-shaped test used one 60-byte token,
	// which is right for aes256-sha1-96 only. A layer that hardcodes any single
	// size passes that and fails on a real AES session.
	for (size_t token_len : kTokenSizes) {
		FakeSealProvider seal(token_len, 2888);
		FakeSealProvider unseal(token_len, 2888);
		const Bytes body = Str("<Envelope><Body><Discover/></Body></Envelope>");
		const Bytes wire = sealing::SealMessage(seal, body);
		REQUIRE_EQ(sealing::UnsealMessage(unseal, wire), body);
	}
}

TEST_CASE("the BOM is sealed as its own frame ahead of the body") {
	FakeSealProvider p(16, 2888);
	const Bytes wire = sealing::SealMessage(p, Str("abc"));
	// Two frames: the 3-byte BOM and the 3-byte body.
	REQUIRE_EQ(p.frames_sealed(), 2u);
	REQUIRE_EQ(wire[0], 3);
	REQUIRE_EQ(wire.size(), (4u + 3u + 16u) * 2u);
}

TEST_CASE("the BOM is stripped on the way back, not handed to the parser") {
	FakeSealProvider seal(16, 2888);
	FakeSealProvider unseal(16, 2888);
	const Bytes wire = sealing::SealMessage(seal, Str("<Envelope/>"));
	const Bytes plain = sealing::UnsealMessage(unseal, wire);
	REQUIRE_EQ(plain, Str("<Envelope/>"));
}

TEST_CASE("a body longer than the chunk size becomes several frames") {
	FakeSealProvider seal(16, 100);
	FakeSealProvider unseal(16, 100);
	const Bytes body(250, 'x');
	const Bytes wire = sealing::SealMessage(seal, body);
	// One BOM frame plus ceil(250/100) = 3 body frames.
	REQUIRE_EQ(seal.frames_sealed(), 4u);
	REQUIRE_EQ(sealing::UnsealMessage(unseal, wire), body);
}

TEST_CASE("a payload landing exactly on a chunk boundary makes no empty frame") {
	FakeSealProvider seal(16, 100);
	FakeSealProvider unseal(16, 100);
	const Bytes body(200, 'y');
	const Bytes wire = sealing::SealMessage(seal, body);
	REQUIRE_EQ(seal.frames_sealed(), 3u);  // BOM + exactly two full chunks
	REQUIRE_EQ(sealing::UnsealMessage(unseal, wire), body);
}

TEST_CASE("a truncated frame BODY is incomplete, not malformed") {
	FakeSealProvider seal(16, 2888);
	FakeSealProvider unseal(16, 2888);
	Bytes wire = sealing::SealMessage(seal, Str("<Envelope/>"));
	wire.resize(wire.size() - 5);
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, sealing::UnsealMessage(unseal, wire));
}

TEST_CASE("a 1-to-3 byte partial header is incomplete, not silently discarded") {
	// This is the case that used to fall out of a loop condition and be dropped
	// in silence, handing the caller short plaintext with no error at all.
	FakeSealProvider seal(16, 2888);
	const Bytes full = sealing::SealMessage(seal, Str("<Envelope/>"));
	for (size_t extra = 1; extra <= 3; extra++) {
		FakeSealProvider unseal(16, 2888);
		Bytes wire(full.begin(), full.end());
		wire.resize(4 + 3 + 16 + extra);  // one whole frame, then a partial header
		REQUIRE_THROWS_EXACTLY(IncompleteMessage, sealing::UnsealMessage(unseal, wire));
	}
}

TEST_CASE("a declared size larger than the buffer does not wrap into a pass") {
	FakeSealProvider p(16, 2888);
	Bytes wire(4 + 4, 0);
	wire[0] = 0xFF;
	wire[1] = 0xFF;	 // dataSize = 65535, far past the buffer
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, sealing::UnsealMessage(p, wire));

	Bytes wire2(4 + 4, 0);
	wire2[0] = 0x02;
	wire2[1] = 0x00;  // dataSize = 2
	wire2[2] = 0xFF;
	wire2[3] = 0xFF;  // tokenSize = 65535
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, sealing::UnsealMessage(p, wire2));
}

TEST_CASE("a mechanism that pads is refused, naming the missing field") {
	// The frame has two length fields and NEITHER carries the unpadded plaintext
	// length. Measured zero for NTLM and every AES enctype, so this guards a
	// mechanism we have not met rather than an expected path.
	FakeSealProvider padding(16, 2888, /*padding=*/8);
	bool threw = false;
	try {
		sealing::SealFrame(padding, Str("abc"));
	} catch (const ProtocolError &e) {
		threw = true;
		REQUIRE(std::string(e.what()).find("unpadded length") != std::string::npos);
	}
	REQUIRE(threw);
}

TEST_CASE("a frame past the uint16 fields is refused, not truncated") {
	FakeSealProvider p(16, 70000);
	REQUIRE_THROWS_EXACTLY(ProtocolError, sealing::SealFrame(p, Bytes(70000, 'z')));
}

TEST_CASE("the reader tolerates a token size it did not choose") {
	// tokenSize is read from the header, never assumed: a Kerberos response can
	// carry 60, 64 or 72 bytes depending on the session key's enctype.
	for (size_t token_len : kTokenSizes) {
		FakeSealProvider seal(token_len, 2888);
		FakeSealProvider unseal(token_len, 2888);
		const Bytes wire = sealing::SealMessage(seal, Str("payload"));
		// The second frame's tokenSize field must say what the provider produced.
		const size_t second = 4 + 3 + token_len;
		const size_t declared = wire[second + 2] | (wire[second + 3] << 8);
		REQUIRE_EQ(declared, token_len);
		REQUIRE_EQ(sealing::UnsealMessage(unseal, wire), Str("payload"));
	}
}
