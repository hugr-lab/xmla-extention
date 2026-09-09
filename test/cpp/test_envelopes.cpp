#include "harness.hpp"
#include "xmla/envelopes.hpp"
#include "xmla/errors.hpp"
#include "xmla/rowset.hpp"

#include <clocale>
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
	// A real query that still contains characters needing escaping: comparison
	// operators and ampersands are ordinary in both MDX and DAX.
	REQUIRE(
		Has(Execute("EVALUATE FILTER(T, [a] < 5)", "", ""), "<Statement>EVALUATE FILTER(T, [a] &lt; 5)</Statement>"));
	REQUIRE(Has(Execute("EVALUATE T", "Cat&Dog", ""), "<Catalog>Cat&amp;Dog</Catalog>"));
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
	// Discover is read-only BY CONSTRUCTION: no builder exists, so no argument
	// reaches one. This asserts the surface; adding a Create/Alter builder would
	// require deleting this test, which is a review event rather than a silent
	// one.
	//
	// Note what this does NOT prove. An earlier version of this test was the
	// ONLY evidence for "read-only by construction" covering Execute as well,
	// and it could not have failed: no MDX or DMX mutation contains the literal
	// "<Create". Execute is covered by the cases below instead.
	const std::string env = Execute("EVALUATE ROW(\"x\", 1)", "", "");
	REQUIRE(Has(env, "<Statement>"));
	REQUIRE(!Has(env, "<Create"));
	REQUIRE(!Has(env, "<Alter"));
	REQUIRE(!Has(env, "<Delete"));
	REQUIRE(!Has(env, "<Refresh"));
}

TEST_CASE("Execute refuses a statement that mutates the server") {
	// <Statement> is the entry point to the WHOLE command surface, not just to
	// queries. Every one of these builds a well-formed envelope that a server
	// would accept and apply, through a path the spec used to claim did not
	// exist.
	const char *mutating[] = {
		"UPDATE CUBE [Sales] SET ([Measures].[Amount]) = 0",  // MDX writeback
		"INSERT INTO [Model] (col) VALUES (1)",				  // DMX
		"DELETE FROM [Mining Model].CONTENT",				  // DMX
		"DROP MINING MODEL [M]",							  // DMX
		"CREATE MINING MODEL [M] ([k] LONG KEY)",			  // DMX
		"ALTER CUBE [Sales] ...",							  // MDX
		"CALL SystemRestoreBackup('x')",					  // stored procedure
		"REFRESH CUBE [Sales]",
		"BACKUP DATABASE [Model] TO 'x.abf'",
		"RESTORE DATABASE [Model] FROM 'x.abf'",
	};
	for (const char *stmt : mutating) {
		REQUIRE_THROWS_EXACTLY(ProtocolError, Execute(stmt, "", ""));
	}
}

TEST_CASE("Execute accepts the query forms, in any casing and with leading trivia") {
	// The allowlist must not be so tight that it refuses real queries.
	const char *queries[] = {
		"SELECT {} ON 0 FROM [Sales]",
		"select {} on 0 from [Sales]",
		"  \t\n EVALUATE Sales",
		"WITH MEMBER [Measures].[X] AS 1 SELECT {} ON 0 FROM [Sales]",
		"DEFINE VAR x = 1 EVALUATE ROW(\"a\", x)",
		"VAR x = 1 RETURN x",
		"// a comment first\nEVALUATE Sales",
		"/* block */ EVALUATE Sales",
		"-- dashes\nEVALUATE Sales",
	};
	for (const char *stmt : queries) {
		const std::string env = Execute(stmt, "", "");
		REQUIRE(Has(env, "<Statement>"));
	}
}

TEST_CASE("a comment cannot hide a mutating keyword from the allowlist") {
	// Comments are SKIPPED to find the first significant token, not merely
	// tolerated at position zero. Checking the raw first characters instead
	// would let "/*x*/ UPDATE CUBE" through.
	REQUIRE_THROWS_EXACTLY(ProtocolError, Execute("/* EVALUATE */ UPDATE CUBE [S] SET (x) = 0", "", ""));
	REQUIRE_THROWS_EXACTLY(ProtocolError, Execute("// EVALUATE\nDROP MINING MODEL [M]", "", ""));
	REQUIRE_THROWS_EXACTLY(ProtocolError, Execute("   \n\t  CALL Something()", "", ""));
}

TEST_CASE("a mutating statement cannot hide behind a query in a batch") {
	// Checking only the FIRST keyword is the classic allowlist bypass. SSMS
	// sends semicolon-separated MDX as a single XMLA Execute/Statement, so a
	// first-token check would carry a writeback behind a harmless SELECT.
	const char *batches[] = {
		"SELECT {} ON 0 FROM [Sales]; UPDATE CUBE [Sales] SET ([Measures].[Amount]) = 0",
		"WITH MEMBER [M] AS 1 SELECT {} ON 0 FROM [S]; DROP MINING MODEL [M]",
		"EVALUATE Sales; EVALUATE Other",
		"EVALUATE Sales ;\n  DELETE FROM [M].CONTENT",
		"EVALUATE Sales; // trailing comment does not make it one statement\nCALL X()",
	};
	for (const char *stmt : batches) {
		REQUIRE_THROWS_EXACTLY(ProtocolError, Execute(stmt, "", ""));
	}
}

TEST_CASE("a separator inside a literal or an identifier is not a separator") {
	// Refusing these would break legitimate queries, which is how a guard gets
	// switched off entirely.
	const char *fine[] = {
		"EVALUATE FILTER(T, [a] = \"x;y\")",
		"EVALUATE FILTER(T, [a] = 'x;y')",
		"SELECT {} ON 0 FROM [Cube;With;Semicolons]",
		"EVALUATE ROW(\"k\", \"a;b\")",
		"EVALUATE Sales;",	// a trailing separator carries nothing
		"EVALUATE Sales;   \n\t  ",
		"EVALUATE Sales; // just a comment",
	};
	for (const char *stmt : fine) {
		const std::string env = Execute(stmt, "", "");
		REQUIRE(Has(env, "<Statement>"));
	}
}

TEST_CASE("the allowlist does not depend on the process locale") {
	// ::toupper follows LC_CTYPE, and a DuckDB extension runs inside a host that
	// may have called setlocale -- CPython does. Under tr_TR.UTF-8, toupper('i')
	// is not 'I', so "with"/"define" would fold to "WiTH"/"DEFiNE" and a valid
	// query would be refused. Keyword syntax is ASCII by definition.
	const char *previous = setlocale(LC_CTYPE, nullptr);
	std::string saved = previous ? previous : "C";
	// Best effort: if the locale is unavailable on this machine the test still
	// exercises the ASCII path, it just cannot demonstrate the difference.
	setlocale(LC_CTYPE, "tr_TR.UTF-8");
	const std::string env = Execute("with member [M] as 1 select {} on 0 from [S]", "", "");
	REQUIRE(Has(env, "<Statement>"));
	Execute("define var x = 1 evaluate ROW(\"a\", x)", "", "");
	setlocale(LC_CTYPE, saved.c_str());
}

TEST_CASE("the refusal does not echo the statement back") {
	// The statement is caller text and the message can reach a log.
	bool threw = false;
	try {
		Execute("UPDATE CUBE [Secret Cube Name] SET ([Measures].[Salary]) = 0", "", "");
	} catch (const ProtocolError &e) {
		threw = true;
		const std::string what = e.what();
		REQUIRE(!Has(what, "Secret Cube Name"));
		REQUIRE(!Has(what, "Salary"));
		REQUIRE(Has(what, "UPDATE"));  // the keyword alone is enough to act on
	}
	REQUIRE(threw);
}
