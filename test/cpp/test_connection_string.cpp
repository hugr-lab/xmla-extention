#include "harness.hpp"
#include "xmla/connection_string.hpp"
#include "xmla/errors.hpp"

#include <string>

using namespace xmla;

static std::string Get(const std::map<std::string, std::string> &m, const std::string &k) {
	const auto it = m.find(k);
	return it == m.end() ? std::string("<absent>") : it->second;
}

TEST_CASE("space-separated pairs are the documented form and must parse") {
	// The first version of this parser split only on ';', so `host=x port=2383`
	// became ONE pair whose value was "x port=2383" — and the port silently
	// stayed unset, surfacing as "port is required" against a string that
	// plainly contains one.
	const auto o = ParseConnectionString("host=ssas-host port=2383 mechanism=ntlm");
	REQUIRE_EQ(Get(o, "host"), std::string("ssas-host"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));
	REQUIRE_EQ(Get(o, "mechanism"), std::string("ntlm"));
}

TEST_CASE("semicolon-separated pairs parse too") {
	const auto o = ParseConnectionString("host=h;port=2383;catalog=Model");
	REQUIRE_EQ(Get(o, "host"), std::string("h"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));
	REQUIRE_EQ(Get(o, "catalog"), std::string("Model"));
}

TEST_CASE("a value may contain spaces without swallowing the next key") {
	// Catalog names routinely contain spaces. The value runs to the next `key=`
	// token, so this must yield both, not a catalog called "Adventure Works
	// port=2383".
	const auto o = ParseConnectionString("catalog=Adventure Works port=2383");
	REQUIRE_EQ(Get(o, "catalog"), std::string("Adventure Works"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));
}

TEST_CASE("a quoted value can contain anything, including a key-shaped word") {
	const auto o = ParseConnectionString("catalog='port=9 is part of the name' port=2383");
	REQUIRE_EQ(Get(o, "catalog"), std::string("port=9 is part of the name"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));

	const auto d = ParseConnectionString("catalog=\"a;b\" port=1");
	REQUIRE_EQ(Get(d, "catalog"), std::string("a;b"));
	REQUIRE_EQ(Get(d, "port"), std::string("1"));
}

TEST_CASE("keys are case-insensitive, values are not") {
	const auto o = ParseConnectionString("HOST=MixedCase PORT=2383");
	REQUIRE_EQ(Get(o, "host"), std::string("MixedCase"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));
}

TEST_CASE("an empty value is kept, not dropped") {
	// `user=` means "the ambient identity" and is different from omitting it.
	const auto o = ParseConnectionString("host=h port=1 user=");
	REQUIRE_EQ(Get(o, "user"), std::string(""));
}

TEST_CASE("a duplicate key is an error, not last-wins") {
	// Last-wins would let `port=2383 port=2384` connect somewhere the caller did
	// not name, and a wrong port presents as a hang.
	REQUIRE_THROWS_EXACTLY(ProtocolError, ParseConnectionString("port=2383 port=2384"));
}

TEST_CASE("malformed input is refused, and the message does not echo it") {
	// The string can carry a host or an account name, and this message can reach
	// a log.
	// None of these may appear as a substring of the message. "=value" would
	// have — the message's own phrase is "key=value pairs" — and the assertion
	// duly failed on it, which is the test catching itself rather than the code.
	const char *bad[] = {"not-a-pair", "=someinstance", "somehostname", "123=x", "-h=1"};
	for (const char *input : bad) {
		bool threw = false;
		try {
			ParseConnectionString(input);
		} catch (const ProtocolError &e) {
			threw = true;
			REQUIRE(std::string(e.what()).find(input) == std::string::npos);
		}
		REQUIRE(threw);
	}
	REQUIRE_THROWS_EXACTLY(ProtocolError, ParseConnectionString("catalog='unterminated"));
}

TEST_CASE("a bare word after a value belongs to that value, and that is deliberate") {
	// `host=h nonsense` is NOT malformed: an unquoted value runs to the next
	// key= token, so the value is "h nonsense". That follows from wanting
	// `catalog=Adventure Works` to work, and the two cannot both be had.
	//
	// The footgun it might seem to open is closed elsewhere: a MISSPELLED key
	// (`porta=2383`) is still a key token, so it is reported as an unknown
	// option rather than being absorbed into the previous value.
	const auto o = ParseConnectionString("host=h nonsense");
	REQUIRE_EQ(Get(o, "host"), std::string("h nonsense"));

	const auto typo = ParseConnectionString("host=h porta=2383");
	REQUIRE_EQ(Get(typo, "host"), std::string("h"));
	REQUIRE_EQ(Get(typo, "porta"), std::string("2383"));
}

TEST_CASE("an empty or whitespace string yields no options rather than throwing") {
	REQUIRE_EQ(ParseConnectionString("").size(), 0u);
	REQUIRE_EQ(ParseConnectionString("   \t\n ").size(), 0u);
	REQUIRE_EQ(ParseConnectionString(";;;").size(), 0u);
}

TEST_CASE("trailing and leading separators are tolerated") {
	const auto o = ParseConnectionString("  ;host=h; port=2383 ;  ");
	REQUIRE_EQ(Get(o, "host"), std::string("h"));
	REQUIRE_EQ(Get(o, "port"), std::string("2383"));
}
