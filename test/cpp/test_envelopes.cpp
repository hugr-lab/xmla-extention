#include "harness.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla/rowset.hpp"

#include <string>

using namespace xmla;
using namespace xmla::envelopes;

static bool Has(const std::string &haystack, const std::string &needle) {
	return haystack.find(needle) != std::string::npos;
}

TEST_CASE("Authenticate uses the extension namespace, NOT the XMLA one") {
	// A live server rejects the XMLA namespace outright: "The Authenticate
	// element ... cannot appear under Envelope/Body".
	const std::string env = Authenticate("dG9rZW4=");
	REQUIRE(Has(env, EXT_NS));
	REQUIRE(!Has(env, std::string("<Authenticate xmlns=\"") + XMLA_NS));
	REQUIRE(Has(env, "<SspiHandshake>dG9rZW4=</SspiHandshake>"));
}

TEST_CASE("Discover and Execute use the XMLA namespace") {
	REQUIRE(Has(Discover("DISCOVER_DATASOURCES", {}, "", ""), std::string("<Discover xmlns=\"") + XMLA_NS));
	REQUIRE(Has(Execute("EVALUATE X", "", ""), std::string("<Execute xmlns=\"") + XMLA_NS));
}

TEST_CASE("the first request sends BeginSession and a later one sends the id") {
	REQUIRE(Has(Discover("X", {}, "", ""), "<BeginSession"));
	const std::string later = Discover("X", {}, "", "SID-1");
	REQUIRE(Has(later, "SessionId=\"SID-1\""));
	REQUIRE(!Has(later, "<BeginSession"));
}

TEST_CASE("restriction VALUES are escaped") {
	const std::string env = Discover("DBSCHEMA_TABLES", {{"TABLE_NAME", "a<b&c\"d"}}, "", "");
	REQUIRE(Has(env, "<TABLE_NAME>a&lt;b&amp;c&quot;d</TABLE_NAME>"));
}

TEST_CASE("restriction NAMES are rejected, not escaped") {
	// An element NAME cannot be made safe by escaping. This is the one parameter
	// through which caller text reaches the wire as markup rather than content,
	// so a crafted value could otherwise close RestrictionList and inject
	// siblings.
	const char *bad[] = {"TABLE NAME", "TABLE-NAME", "1TABLE", "", "A></A><Injected>x</Injected><A>", "A/B"};
	for (const char *name : bad) {
		REQUIRE_THROWS_EXACTLY(ProtocolError, Discover("X", {{name, "v"}}, "", ""));
	}
	// And a legitimate one is accepted.
	Discover("X", {{"CATALOG_NAME", "v"}}, "", "");
	Discover("X", {{"_LEADING_UNDERSCORE", "v"}}, "", "");
}

TEST_CASE("the catalog and the statement are escaped") {
	REQUIRE(Has(Execute("a < b", "Cat&Dog", ""), "<Statement>a &lt; b</Statement>"));
	REQUIRE(Has(Execute("x", "Cat&Dog", ""), "<Catalog>Cat&amp;Dog</Catalog>"));
}

TEST_CASE("an escaped envelope survives a round-trip through the parser") {
	// The two halves must agree: what XmlEscape writes, ParseRowset must read
	// back unchanged. A mismatch shows up as silently corrupted values.
	const std::string value = "a<b>&\"'z";
	const std::string doc = "<row><V>" + XmlEscape(value) + "</V></row>";
	const Rowset rs = ParseRowset(doc);
	REQUIRE_EQ(rs.rows[0].at("V"), value);
}

TEST_CASE("there is no builder for a mutating command") {
	// Constitution II is absence of capability, not a gate. This asserts the
	// header's surface: if a Create/Alter/Delete/Refresh builder is ever added,
	// this test is the thing that has to be deleted to make it compile away -
	// which is a review event rather than a silent one.
	const std::string env = Execute("EVALUATE ROW(\"x\", 1)", "", "");
	REQUIRE(Has(env, "<Statement>"));
	REQUIRE(!Has(env, "<Create"));
	REQUIRE(!Has(env, "<Alter"));
	REQUIRE(!Has(env, "<Delete"));
	REQUIRE(!Has(env, "<Refresh"));
}
