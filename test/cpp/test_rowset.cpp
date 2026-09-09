#include "harness.hpp"
#include "xmla/rowset.hpp"

#include <string>

using namespace xmla;

static const char *kDiscoverResponse = R"(<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 <soap:Body>
  <DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">
   <return>
    <root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">
     <row><CATALOG_NAME>Adventure Works</CATALOG_NAME><TYPE>3</TYPE></row>
     <row><CATALOG_NAME>Sales &amp; Ops</CATALOG_NAME><TYPE>0</TYPE><DESCRIPTION/></row>
    </root>
   </return>
  </DiscoverResponse>
 </soap:Body>
</soap:Envelope>)";

TEST_CASE("rows are parsed by local name, whatever the namespace") {
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE_EQ(rs.size(), 2u);
	REQUIRE_EQ(rs.rows[0].at("CATALOG_NAME"), std::string("Adventure Works"));
	REQUIRE_EQ(rs.rows[0].at("TYPE"), std::string("3"));
	REQUIRE_EQ(rs.rows[1].at("TYPE"), std::string("0"));
}

TEST_CASE("entities in values are decoded") {
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE_EQ(rs.rows[1].at("CATALOG_NAME"), std::string("Sales & Ops"));
}

TEST_CASE("a self-closing column is an empty value, not an absent one") {
	// XMLA omits a null column entirely, so "" and "absent" mean different
	// things and must not be collapsed.
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE(rs.rows[1].find("DESCRIPTION") != rs.rows[1].end());
	REQUIRE_EQ(rs.rows[1].at("DESCRIPTION"), std::string(""));
	REQUIRE(rs.rows[0].find("DESCRIPTION") == rs.rows[0].end());
}

TEST_CASE("columns are the union across rows, in first-seen order") {
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE_EQ(rs.columns.size(), 3u);
	REQUIRE_EQ(rs.columns[0], std::string("CATALOG_NAME"));
	REQUIRE_EQ(rs.columns[1], std::string("TYPE"));
	REQUIRE_EQ(rs.columns[2], std::string("DESCRIPTION"));
}

TEST_CASE("an empty rowset parses to zero rows, not to an error") {
	// "no catalogs visible to this account" is a MEANINGFUL answer, distinct
	// from a refusal.
	const Rowset rs = ParseRowset("<root xmlns=\"urn:x:rowset\"></root>");
	REQUIRE_EQ(rs.size(), 0u);
	REQUIRE(rs.empty());
}

TEST_CASE("a SOAP fault is found and its parts separated") {
	const std::string fault = R"(<soap:Envelope><soap:Body><soap:Fault>
      <faultcode>XMLAnalysisError.0xc10e0002</faultcode>
      <faultstring>The user does not have permission.</faultstring>
    </soap:Fault></soap:Body></soap:Envelope>)";
	const Fault f = FindFault(fault);
	REQUIRE(f.present);
	REQUIRE_EQ(f.code, std::string("XMLAnalysisError.0xc10e0002"));
	REQUIRE_EQ(f.message, std::string("The user does not have permission."));
}

TEST_CASE("a normal response carries no fault") {
	REQUIRE(!FindFault(kDiscoverResponse).present);
}

TEST_CASE("a comment containing markup does not become markup") {
	// A scanner that does not skip comments reads their contents as tags, and a
	// server's own diagnostic comment could then inject rows.
	const std::string doc =
		"<root xmlns=\"urn:x:rowset\">"
		"<!-- <row><EVIL>1</EVIL></row> -->"
		"<row><OK>2</OK></row></root>";
	const Rowset rs = ParseRowset(doc);
	REQUIRE_EQ(rs.size(), 1u);
	REQUIRE_EQ(rs.rows[0].at("OK"), std::string("2"));
}

TEST_CASE("CDATA and processing instructions are skipped, not read as markup") {
	const std::string doc =
		"<?xml version=\"1.0\"?><root>"
		"<row><NOTE><![CDATA[<row><X>9</X></row>]]></NOTE></row></root>";
	const Rowset rs = ParseRowset(doc);
	REQUIRE_EQ(rs.size(), 1u);
}

TEST_CASE("an attribute is read by name, and a suffix match is not one") {
	std::string sid;
	REQUIRE(FindAttribute("<Session SessionId=\"ABC123\"/>", "Session", "SessionId", sid));
	REQUIRE_EQ(sid, std::string("ABC123"));

	// "NotSessionId" ends with "SessionId"; matching it would read the wrong
	// value and carry a bogus session for the life of the connection.
	std::string wrong;
	REQUIRE(!FindAttribute("<Session NotSessionId=\"NO\"/>", "Session", "SessionId", wrong));
}

TEST_CASE("truncated and malformed documents terminate rather than run away") {
	// These come off a socket. None may loop, read out of bounds, or throw.
	const char *inputs[] = {"",
							"<",
							"<row",
							"<row>",
							"<row><A>",
							"<!--",
							"<![CDATA[",
							"<?xml",
							"<row><A>&",
							"<row><A>&#;</A></row>",
							"<row><A>&#xZZZZ;</A></row>",
							"<row><A>&notanentity;</A></row>",
							"</row>",
							"<><><>",
							"<row/><row/>"};
	for (const char *in : inputs) {
		const Rowset rs = ParseRowset(in);
		(void)rs;
		const Fault f = FindFault(in);
		(void)f;
		std::string tmp;
		FindElementText(in, "faultstring", tmp);
		FindAttribute(in, "Session", "SessionId", tmp);
	}
}

TEST_CASE("an unrecognised entity is passed through, not dropped") {
	// Dropping it silently changes a value the caller may compare against a
	// server-side one. Passing it through is visibly wrong instead.
	const Rowset rs = ParseRowset("<row><A>a&nbsp;b</A></row>");
	REQUIRE_EQ(rs.rows[0].at("A"), std::string("a&nbsp;b"));
}

TEST_CASE("a surrogate code point is left literal, not encoded as CESU-8") {
	// Surrogates are not Unicode scalar values. The 3-byte branch would emit
	// CESU-8, and DuckDB's VARCHAR requires well-formed UTF-8 — so it would
	// surface as an invalid-UTF-8 error attributed to the wrong layer.
	const Rowset lo = ParseRowset("<row><A>&#xD800;</A></row>");
	REQUIRE_EQ(lo.rows[0].at("A"), std::string("&#xD800;"));
	const Rowset hi = ParseRowset("<row><A>&#xDFFF;</A></row>");
	REQUIRE_EQ(hi.rows[0].at("A"), std::string("&#xDFFF;"));

	// A genuine astral character still encodes, so the guard is not over-broad.
	const Rowset astral = ParseRowset("<row><A>&#x1F600;</A></row>");
	const std::string v = astral.rows[0].at("A");
	REQUIRE_EQ(v.size(), 4u);
	REQUIRE_EQ(static_cast<unsigned char>(v[0]), 0xF0u);
}

TEST_CASE("an unmatched leading close tag does not silence the whole rowset") {
	// depth was decremented with no floor, so a leading close tag drove it
	// negative, row_depth went negative with it, every `row_depth >= 0` guard
	// failed, and the function returned an EMPTY rowset with no error — which
	// this layer documents as a MEANINGFUL answer ("no catalogs visible to this
	// account"). A silent wrong answer, indistinguishable from a real one.
	const Rowset rs = ParseRowset("</Bogus><row><A>1</A></row>");
	REQUIRE_EQ(rs.size(), 1u);
	REQUIRE_EQ(rs.rows[0].at("A"), std::string("1"));

	const Rowset many = ParseRowset("</a></b></c><root><row><B>2</B></row></root>");
	REQUIRE_EQ(many.size(), 1u);
	REQUIRE_EQ(many.rows[0].at("B"), std::string("2"));
}
