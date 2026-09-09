#include "harness.hpp"
#include "xmla/dime.hpp"
#include "xmla/errors.hpp"

#include <string>

using namespace xmla;
using dime::Bytes;

static Bytes Str(const std::string &s) {
	return Bytes(s.begin(), s.end());
}

TEST_CASE("a record round-trips through encode and decode") {
	dime::Record r;
	r.data = Str("<Envelope/>");
	const Bytes wire = r.Encode();
	size_t next = 0;
	dime::Record back = dime::DecodeRecord(wire.data(), wire.size(), 0, next);
	REQUIRE_EQ(back.data, r.data);
	REQUIRE_EQ(back.type_, std::string(dime::TYPE_TEXT_XML));
	REQUIRE(back.mb);
	REQUIRE(back.me);
	REQUIRE(!back.cf);
	REQUIRE_EQ(next, wire.size());
}

TEST_CASE("every field is padded separately to a 4-byte boundary") {
	// "text/xml" is 8 bytes (no padding); a 3-byte body needs 1 pad byte; a
	// 4-byte OPTIONS needs none. The declared lengths exclude their own padding,
	// so the total is header + 4 + 0 + 8 + 3 + 1.
	dime::Record r;
	r.data = Str("abc");
	const Bytes wire = r.Encode();
	REQUIRE_EQ(wire.size(), dime::HEADER_LEN + 4 + 8 + 4);
	// DATA_LENGTH declares 3, not the padded 4.
	REQUIRE_EQ(wire[11], 3);
}

TEST_CASE("a header shorter than 12 bytes is incomplete, not malformed") {
	dime::Record r;
	r.data = Str("abc");
	const Bytes wire = r.Encode();
	for (size_t n = 0; n < dime::HEADER_LEN; n++) {
		size_t next = 0;
		REQUIRE_THROWS_EXACTLY(IncompleteMessage, dime::DecodeRecord(wire.data(), n, 0, next));
	}
}

TEST_CASE("a record whose PADDING has not arrived is incomplete, not decoded") {
	// The trap this whole layer is shaped around. A 3-byte body declares 3 and
	// is followed by 1 pad byte. If the body has arrived but the pad has not,
	// reporting the record as decoded leaves that byte in the stream, where it
	// is read as the next message's header and surfaces as a bogus
	// "unsupported DIME version" - a desync disguised as a protocol error.
	dime::Record r;
	r.data = Str("abc");
	const Bytes wire = r.Encode();
	size_t next = 0;
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, dime::DecodeRecord(wire.data(), wire.size() - 1, 0, next));
	// One more byte and it decodes.
	dime::Record ok = dime::DecodeRecord(wire.data(), wire.size(), 0, next);
	REQUIRE_EQ(ok.data, r.data);
}

TEST_CASE("a bad version is malformed, NOT incomplete") {
	dime::Record r;
	r.data = Str("abc");
	Bytes wire = r.Encode();
	wire[0] = static_cast<uint8_t>((2 << 3) | 0x06);  // version 2, MB|ME
	size_t next = 0;
	REQUIRE_THROWS_EXACTLY(ProtocolError, dime::DecodeRecord(wire.data(), wire.size(), 0, next));
}

TEST_CASE("a chunked message reassembles across records by MB/CF/ME") {
	dime::Record a;
	a.data = Str("<Env");
	a.mb = true;
	a.me = false;
	a.cf = true;
	dime::Record b;
	b.data = Str("elope/>");
	b.mb = false;
	b.me = true;
	b.cf = false;

	Bytes wire = a.Encode();
	const Bytes tail = b.Encode();
	wire.insert(wire.end(), tail.begin(), tail.end());

	dime::DecodedMessage msg = dime::DecodeMessageAt(wire.data(), wire.size(), 0);
	REQUIRE_EQ(msg.payload, Str("<Envelope/>"));
	REQUIRE_EQ(msg.next_offset, wire.size());
}

TEST_CASE("a chunked message missing its ME record is incomplete, not malformed") {
	// Reclassifying this as malformed is the specific defect that broke chunked
	// messages in the reference implementation: it says nothing about
	// truncation, so a substring match on the message treated it as fatal.
	dime::Record a;
	a.data = Str("<Env");
	a.mb = true;
	a.me = false;
	a.cf = true;
	const Bytes wire = a.Encode();
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, dime::DecodeMessageAt(wire.data(), wire.size(), 0));
}

TEST_CASE("a first record without MB is malformed") {
	dime::Record a;
	a.data = Str("x");
	a.mb = false;
	a.me = true;
	const Bytes wire = a.Encode();
	REQUIRE_THROWS_EXACTLY(ProtocolError, dime::DecodeMessageAt(wire.data(), wire.size(), 0));
}

TEST_CASE("two messages packed into one segment both survive") {
	// A peer may pack several messages into one TCP segment. Consuming the whole
	// buffer per message silently discards whatever followed - which an early
	// version of the reference reader did.
	const Bytes one = dime::EncodeMessage(Str("<A/>"));
	const Bytes two = dime::EncodeMessage(Str("<BB/>"));
	Bytes wire = one;
	wire.insert(wire.end(), two.begin(), two.end());

	dime::DecodedMessage first = dime::DecodeMessageAt(wire.data(), wire.size(), 0);
	REQUIRE_EQ(first.payload, Str("<A/>"));
	REQUIRE_EQ(first.next_offset, one.size());

	dime::DecodedMessage second = dime::DecodeMessageAt(wire.data(), wire.size(), first.next_offset);
	REQUIRE_EQ(second.payload, Str("<BB/>"));
	REQUIRE_EQ(second.next_offset, wire.size());
}

TEST_CASE("the negotiation bits we send are clear, and NEGO is set only afterwards") {
	REQUIRE_EQ(dime::OptionsClearText()[0], 0);
	REQUIRE_EQ(dime::OptionsNegotiated()[0], dime::OPT_NEGO);
	// RESP_XPRESS in particular must never be set: a server asked for
	// compression answers with XPRESS-compressed XML that arrives as convincing
	// binary noise rather than as an error.
	REQUIRE_EQ(dime::OptionsNegotiated()[0] & dime::OPT_RESP_XPRESS, 0);
	REQUIRE_EQ(dime::OptionsClearText()[0] & dime::OPT_RESP_XPRESS, 0);
}

TEST_CASE("a server selecting binary XML or compression raises Negotiation, not Protocol") {
	Bytes sx(4, 0);
	sx[0] = dime::OPT_RESP_SX;
	REQUIRE_THROWS_EXACTLY(NegotiationError, dime::CheckNegotiated(sx, dime::TYPE_TEXT_XML));

	Bytes xpress(4, 0);
	xpress[0] = dime::OPT_RESP_XPRESS;
	REQUIRE_THROWS_EXACTLY(NegotiationError, dime::CheckNegotiated(xpress, dime::TYPE_TEXT_XML));

	REQUIRE_THROWS_EXACTLY(NegotiationError, dime::CheckNegotiated(dime::OptionsClearText(), dime::TYPE_BINARY_XML));

	// The happy path must not throw.
	dime::CheckNegotiated(dime::OptionsNegotiated(), dime::TYPE_TEXT_XML);
}

TEST_CASE("a DATA_LENGTH larger than the buffer is incomplete, and does not wrap") {
	// data_len is a uint32 straight off the wire. On a 32-bit size_t an
	// unguarded `pos + data_len` wraps and passes a bounds check it should fail.
	dime::Record r;
	r.data = Str("abc");
	Bytes wire = r.Encode();
	wire[8] = 0xFF;
	wire[9] = 0xFF;
	wire[10] = 0xFF;
	wire[11] = 0xF0;
	size_t next = 0;
	REQUIRE_THROWS_EXACTLY(IncompleteMessage, dime::DecodeRecord(wire.data(), wire.size(), 0, next));
}
