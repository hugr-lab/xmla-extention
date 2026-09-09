#include "harness.hpp"
#include "xmla/dime.hpp"
#include "xmla/errors.hpp"
#include "xmla/transport.hpp"

#include <memory>
#include <string>

using namespace xmla;

static Bytes Str(const std::string &s) {
	return Bytes(s.begin(), s.end());
}

TEST_CASE("a message survives being delivered one byte at a time") {
	// Reads are driven by the header's declared lengths, never by the peer going
	// quiet. A single-byte chunk size is the harshest form of that.
	auto chan = std::make_shared<BytesChannel>(dime::EncodeMessage(Str("<Envelope/>")));
	chan->SetChunkSize(1);
	MessageStream stream(chan);
	REQUIRE_EQ(stream.ReceiveMessage(), Str("<Envelope/>"));
}

TEST_CASE("a second message packed into the same segment is not discarded") {
	Bytes wire = dime::EncodeMessage(Str("<A/>"));
	const Bytes two = dime::EncodeMessage(Str("<BB/>"));
	wire.insert(wire.end(), two.begin(), two.end());

	auto chan = std::make_shared<BytesChannel>(wire);
	MessageStream stream(chan);
	REQUIRE_EQ(stream.ReceiveMessage(), Str("<A/>"));
	// The reader consumes exactly one message and keeps the remainder. Consuming
	// the whole buffer per message silently drops this second one.
	REQUIRE_EQ(stream.ReceiveMessage(), Str("<BB/>"));
}

TEST_CASE("a peer that closes mid-message raises Connection, not a short read") {
	Bytes wire = dime::EncodeMessage(Str("<Envelope/>"));
	wire.resize(wire.size() - 4);
	auto chan = std::make_shared<BytesChannel>(wire);
	MessageStream stream(chan);
	REQUIRE_THROWS_EXACTLY(ConnectionError, stream.ReceiveMessage());
}

TEST_CASE("a peer that never sets ME is bounded, and the error says which fault it was") {
	// Reclassifying "no ME" as incomplete is right for chunking, but it means an
	// unbounded reader accumulates until the connection closes.
	dime::Record chunked;
	chunked.data = Bytes(64, 'x');
	chunked.mb = true;
	chunked.me = false;
	chunked.cf = true;
	Bytes wire;
	for (int i = 0; i < 200; i++) {
		const Bytes r = chunked.Encode();
		wire.insert(wire.end(), r.begin(), r.end());
	}
	auto chan = std::make_shared<BytesChannel>(wire);
	MessageStream stream(chan, 1024);
	bool threw = false;
	try {
		stream.ReceiveMessage();
	} catch (const IncompleteMessage &) {
		throw harness::Failure("bounded buffer must not surface as IncompleteMessage");
	} catch (const ProtocolError &e) {
		threw = true;
		const std::string what = e.what();
		REQUIRE(what.find("never set ME") != std::string::npos);
		REQUIRE(what.find("desynchronised") != std::string::npos);
	}
	REQUIRE(threw);
}

TEST_CASE("the negotiation check runs on receive, so a compressed reply raises Negotiation") {
	dime::Record r;
	r.data = Str("<compressed/>");
	r.options = dime::OptionsClearText();
	r.options[0] = dime::OPT_RESP_XPRESS;
	auto chan = std::make_shared<BytesChannel>(r.Encode());
	MessageStream stream(chan);
	REQUIRE_THROWS_EXACTLY(NegotiationError, stream.ReceiveMessage());
}

TEST_CASE("the first record sends NEGO clear and a later one sets it") {
	auto chan = std::make_shared<BytesChannel>();
	MessageStream stream(chan);
	stream.SendMessage(Str("<A/>"), dime::OptionsClearText());
	// OPTIONS is the first field after the 12-byte header.
	REQUIRE_EQ(chan->sent()[dime::HEADER_LEN], 0);

	auto chan2 = std::make_shared<BytesChannel>();
	MessageStream stream2(chan2);
	stream2.SendMessage(Str("<A/>"), dime::OptionsNegotiated());
	REQUIRE_EQ(chan2->sent()[dime::HEADER_LEN], dime::OPT_NEGO);
}
