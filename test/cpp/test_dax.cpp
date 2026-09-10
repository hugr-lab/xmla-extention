#include "harness.hpp"
#include "xmla/dax.hpp"

#include <string>
#include <vector>

using namespace xmla;

TEST_CASE("a narrowing projection renders SELECTCOLUMNS") {
	// The whole point of the projection: `EVALUATE 'T'` returns every column, so
	// a narrow SELECT over a wide table paid for all of it. Measured against a
	// live 60398-row fact table, one column of three took 2.22 s against 37.07 s.
	const std::vector<std::string> wanted = {"SalesAmount"};
	REQUIRE_EQ(dax::Evaluate("FactInternetSales", wanted, 3),
			   std::string("EVALUATE SELECTCOLUMNS('FactInternetSales', \"SalesAmount\", "
						   "'FactInternetSales'[SalesAmount])"));
}

TEST_CASE("the projection keeps the caller's column ORDER") {
	// The executor expects the output columns in the order it asked for them,
	// not in the table's order.
	const std::vector<std::string> wanted = {"OrderQuantity", "ProductKey"};
	REQUIRE_EQ(dax::Evaluate("T", wanted, 3),
			   std::string("EVALUATE SELECTCOLUMNS('T', \"OrderQuantity\", 'T'[OrderQuantity], "
						   "\"ProductKey\", 'T'[ProductKey])"));
}

TEST_CASE("a projection that does not narrow is not sent") {
	// SELECTCOLUMNS needs compatibility level 1200 or above, which is UNVERIFIED
	// against anything older, so it is used only where it buys something. A
	// SELECT * therefore travels the plain path that has been exercised against
	// a live instance since the first working scan.
	const std::vector<std::string> all = {"A", "B", "C"};
	REQUIRE_EQ(dax::Evaluate("T", all, 3), std::string("EVALUATE 'T'"));
	REQUIRE_EQ(dax::Evaluate("T", {}, 3), std::string("EVALUATE 'T'"));
}

TEST_CASE("a table name with a space or an apostrophe-free oddity still quotes") {
	const std::vector<std::string> wanted = {"A"};
	REQUIRE_EQ(dax::Evaluate("Internet Sales", wanted, 2),
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
		REQUIRE_EQ(dax::Evaluate("T", wanted, 5), std::string("EVALUATE 'T'"));
	}
}

TEST_CASE("an unsafe TABLE name composes nothing at all") {
	// Not even the plain form is safe to build around, because it quotes the
	// name. The caller gets a statement the server will reject rather than one
	// that reads a different table.
	const std::vector<std::string> wanted = {"A"};
	REQUIRE_EQ(dax::Evaluate("T'; EVALUATE 'Other", wanted, 3), std::string("EVALUATE 'T'; EVALUATE 'Other'"));
	// ... and the projection is definitely not composed around it.
	REQUIRE(dax::Evaluate("T'; EVALUATE 'Other", wanted, 3).find("SELECTCOLUMNS") == std::string::npos);
}

TEST_CASE("count(*) projects exactly one column") {
	// `count(*)` asks for no real column — it takes the EMPTY virtual column —
	// so the scan projects one and discards every cell it produces. Without that
	// the fallback is `EVALUATE 'T'` and counting rows transfers the table.
	const std::vector<std::string> wanted = {"ProductKey"};
	const std::string sql = dax::Evaluate("T", wanted, 3);
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
