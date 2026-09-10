#include "harness.hpp"
#include "xmla/dax.hpp"
#include "xmla/errors.hpp"

#include <string>
#include <vector>

using namespace xmla;

TEST_CASE("a narrowing projection renders SELECTCOLUMNS") {
	// The whole point of the projection: `EVALUATE 'T'` returns every column, so
	// a narrow SELECT over a wide table paid for all of it. Measured against a
	// live 60398-row fact table, one column of three took 2.22 s against 37.07 s.
	const std::vector<std::string> wanted = {"SalesAmount"};
	REQUIRE_EQ(dax::Evaluate("FactInternetSales", wanted, 3, true),
			   std::string("EVALUATE SELECTCOLUMNS('FactInternetSales', \"SalesAmount\", "
						   "'FactInternetSales'[SalesAmount])"));
}

TEST_CASE("the projection keeps the caller's column ORDER") {
	// The executor expects the output columns in the order it asked for them,
	// not in the table's order.
	const std::vector<std::string> wanted = {"OrderQuantity", "ProductKey"};
	REQUIRE_EQ(dax::Evaluate("T", wanted, 3, true),
			   std::string("EVALUATE SELECTCOLUMNS('T', \"OrderQuantity\", 'T'[OrderQuantity], "
						   "\"ProductKey\", 'T'[ProductKey])"));
}

TEST_CASE("a projection that does not narrow is not sent") {
	// SELECTCOLUMNS needs compatibility level 1200 or above, which is UNVERIFIED
	// against anything older, so it is used only where it buys something. A
	// SELECT * therefore travels the plain path that has been exercised against
	// a live instance since the first working scan.
	const std::vector<std::string> all = {"A", "B", "C"};
	REQUIRE_EQ(dax::Evaluate("T", all, 3, true), std::string("EVALUATE 'T'"));
	REQUIRE_EQ(dax::Evaluate("T", {}, 3, true), std::string("EVALUATE 'T'"));
}

TEST_CASE("a table name with a space or an apostrophe-free oddity still quotes") {
	const std::vector<std::string> wanted = {"A"};
	REQUIRE_EQ(dax::Evaluate("Internet Sales", wanted, 2, true),
			   std::string("EVALUATE SELECTCOLUMNS('Internet Sales', \"A\", 'Internet Sales'[A])"));
}

TEST_CASE("an unsafe COLUMN name disables the whole projection, not part of it") {
	// A partial projection returns fewer columns than the caller expects, which
	// is a wrong answer rather than a slow one. These names come from the
	// server's own DBSCHEMA_COLUMNS, so one carrying a bracket is either a
	// server not to trust or a case nobody has tested; both say stop composing.
	const char *unsafe[] = {"A]", "A[", "A'", "A\"", "A\nB", "A\tB", ""};
	for (const char *name : unsafe) {
		const std::vector<std::string> wanted = {"Safe", name};
		REQUIRE_EQ(dax::Evaluate("T", wanted, 5, true), std::string("EVALUATE 'T'"));
	}
}

TEST_CASE("an unsafe TABLE name is REFUSED, not emitted in a quoted context") {
	// There is nothing safe to compose around it: the plain form quotes the name
	// too, so falling back to `EVALUATE '<name>'` emitted the rejected string
	// verbatim and left the operator with a DAX syntax error they could not
	// attribute to anything. An earlier version of this case asserted exactly
	// that output while being NAMED "composes nothing at all".
	const std::vector<std::string> wanted = {"A"};
	REQUIRE_THROWS_EXACTLY(ProtocolError, dax::Evaluate("T'; EVALUATE 'Other", wanted, 3, true));
	REQUIRE_THROWS_EXACTLY(ProtocolError, dax::Evaluate("T]", wanted, 3, true));
	REQUIRE_THROWS_EXACTLY(ProtocolError, dax::Evaluate("", wanted, 3, true));
}

TEST_CASE("a placeholder column list is never projected") {
	// When DBSCHEMA_COLUMNS showed nothing, the catalog advertises one synthetic
	// column so the table stays describable. Naming it turns a scan that
	// returned something into a query-time DAX error, so columns_known=false
	// forbids the projection — as a RULE, not as an accident of the count. It
	// was safe before only because the placeholder happens to be exactly one
	// column, which can never narrow; a second one would have started sending
	// SELECTCOLUMNS for a column the server does not have.
	const std::vector<std::string> wanted = {"unknown"};
	REQUIRE_EQ(dax::Evaluate("T", wanted, 3, false), std::string("EVALUATE 'T'"));
	// ... and the same list IS projected once the columns are real.
	REQUIRE(dax::Evaluate("T", wanted, 3, true).find("SELECTCOLUMNS") != std::string::npos);
}

TEST_CASE("count(*) projects exactly one column") {
	// `count(*)` asks for no real column — it takes the EMPTY virtual column —
	// so the scan projects one and discards every cell it produces. Without that
	// the fallback is `EVALUATE 'T'` and counting rows transfers the table.
	const std::vector<std::string> wanted = {"ProductKey"};
	const std::string sql = dax::Evaluate("T", wanted, 3, true);
	REQUIRE(sql.find("SELECTCOLUMNS") != std::string::npos);
	// One name, one reference: no second column crept in.
	REQUIRE_EQ(sql.find("'T'[ProductKey]"), sql.rfind("'T'[ProductKey]"));
}

TEST_CASE("a string literal doubles a quote rather than refusing it") {
	// A value is not an identifier: a caller's own search term legitimately
	// contains quotes.
	REQUIRE_EQ(dax::StringLiteral("plain"), std::string("\"plain\""));
	REQUIRE_EQ(dax::StringLiteral("say \"hi\""), std::string("\"say \"\"hi\"\"\""));
	REQUIRE_EQ(dax::StringLiteral(""), std::string("\"\""));
}

TEST_CASE("SafeName accepts what a real model uses and refuses the rest") {
	REQUIRE(dax::SafeName("ProductKey"));
	REQUIRE(dax::SafeName("English Product Name"));
	REQUIRE(dax::SafeName("Sales & Ops"));
	REQUIRE(dax::SafeName("__Count of DimProduct"));
	REQUIRE(!dax::SafeName(""));
	REQUIRE(!dax::SafeName("a]b"));
	REQUIRE(!dax::SafeName("a[b"));
	REQUIRE(!dax::SafeName("a'b"));
	REQUIRE(!dax::SafeName("a\"b"));
	REQUIRE(!dax::SafeName(std::string("a\0b", 3)));
	REQUIRE(!dax::SafeName("a\x7f"));
}
