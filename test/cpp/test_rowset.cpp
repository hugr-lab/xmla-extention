#include "harness.hpp"
#include "xmla/rowset.hpp"

#include <string>
#include <vector>

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
	REQUIRE_EQ(rs.Row(0).At("CATALOG_NAME"), std::string("Adventure Works"));
	REQUIRE_EQ(rs.Row(0).At("TYPE"), std::string("3"));
	REQUIRE_EQ(rs.Row(1).At("TYPE"), std::string("0"));
}

TEST_CASE("entities in values are decoded") {
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE_EQ(rs.Row(1).At("CATALOG_NAME"), std::string("Sales & Ops"));
}

TEST_CASE("a self-closing column is an empty value, not an absent one") {
	// XMLA omits a null column entirely, so "" and "absent" mean different
	// things and must not be collapsed.
	const Rowset rs = ParseRowset(kDiscoverResponse);
	REQUIRE(rs.Row(1).Has("DESCRIPTION"));
	REQUIRE_EQ(rs.Row(1).At("DESCRIPTION"), std::string(""));
	REQUIRE(!rs.Row(0).Has("DESCRIPTION"));
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
	REQUIRE_EQ(rs.Row(0).At("OK"), std::string("2"));
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
	REQUIRE_EQ(rs.Row(0).At("A"), std::string("a&nbsp;b"));
}

TEST_CASE("a surrogate code point is left literal, not encoded as CESU-8") {
	// Surrogates are not Unicode scalar values. The 3-byte branch would emit
	// CESU-8, and DuckDB's VARCHAR requires well-formed UTF-8 — so it would
	// surface as an invalid-UTF-8 error attributed to the wrong layer.
	const Rowset lo = ParseRowset("<row><A>&#xD800;</A></row>");
	REQUIRE_EQ(lo.Row(0).At("A"), std::string("&#xD800;"));
	const Rowset hi = ParseRowset("<row><A>&#xDFFF;</A></row>");
	REQUIRE_EQ(hi.Row(0).At("A"), std::string("&#xDFFF;"));

	// A genuine astral character still encodes, so the guard is not over-broad.
	const Rowset astral = ParseRowset("<row><A>&#x1F600;</A></row>");
	const std::string v = astral.Row(0).At("A");
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
	REQUIRE_EQ(rs.Row(0).At("A"), std::string("1"));

	const Rowset many = ParseRowset("</a></b></c><root><row><B>2</B></row></root>");
	REQUIRE_EQ(many.size(), 1u);
	REQUIRE_EQ(many.Row(0).At("B"), std::string("2"));
}

TEST_CASE("SSAS XML name encoding is decoded in column names") {
	// EVALUATE ROW("answer", 42) returns a column literally named
	// _x005B_answer_x005D_ — that is [answer]. Unusable as a SQL column name
	// and unrecognisable to whoever wrote the query.
	const Rowset rs = ParseRowset("<row><_x005B_answer_x005D_>42</_x005B_answer_x005D_></row>");
	REQUIRE_EQ(rs.columns.size(), 1u);
	REQUIRE_EQ(rs.columns[0], std::string("[answer]"));
	REQUIRE_EQ(rs.Row(0).At("[answer]"), std::string("42"));
}

TEST_CASE("a name that merely contains _x is left alone") {
	// Only an exact _xHHHH_ is an escape. A column genuinely called my_x_axis
	// must survive, and so must a truncated or non-hex sequence.
	const char *untouched[] = {"my_x_axis", "_xZZZZ_", "_x12_", "col_x", "_x005B", "a_xa_b"};
	for (const char *name : untouched) {
		const std::string doc = std::string("<row><") + name + ">v</" + name + "></row>";
		const Rowset rs = ParseRowset(doc);
		REQUIRE_EQ(rs.columns.size(), 1u);
		REQUIRE_EQ(rs.columns[0], std::string(name));
	}
}

TEST_CASE("a self-closing encoded column decodes too") {
	const Rowset rs = ParseRowset("<row><_x0020_gap/></row>");
	REQUIRE_EQ(rs.columns[0], std::string(" gap"));
}

// --- the incremental parser (T-042) -----------------------------------------

//! Feed `doc` in fixed-size pieces and collect the rows as (column, value) text.
static std::vector<std::string> StreamRows(const std::string &doc, size_t chunk, std::vector<std::string> &columns) {
	RowStreamParser parser;
	std::vector<std::string> out;
	std::vector<Cell> row;
	size_t offset = 0;
	while (offset < doc.size()) {
		const size_t take = (chunk == 0 || offset + chunk > doc.size()) ? doc.size() - offset : chunk;
		parser.Append(doc.data() + offset, take);
		offset += take;
		// Pull whatever is ready BETWEEN feeds, which is the point: a caller that
		// only drained at the end would not exercise resumption at all.
		while (parser.Next(row)) {
			std::string rendered;
			for (const auto &cell : row) {
				rendered += parser.columns()[cell.column] + "=" + cell.value + ";";
			}
			out.push_back(rendered);
		}
	}
	parser.Finish();
	while (parser.Next(row)) {
		std::string rendered;
		for (const auto &cell : row) {
			rendered += parser.columns()[cell.column] + "=" + cell.value + ";";
		}
		out.push_back(rendered);
	}
	columns = parser.columns();
	return out;
}

//! The same rows, from ParseRowset, in the same rendering.
static std::vector<std::string> WholeRows(const std::string &doc) {
	const Rowset rs = ParseRowset(doc);
	std::vector<std::string> out;
	for (size_t r = 0; r < rs.size(); r++) {
		std::string rendered;
		const auto row = rs.Row(r);
		for (const auto *cell = row.begin(); cell != row.end(); ++cell) {
			rendered += rs.columns[cell->column] + "=" + cell->value + ";";
		}
		out.push_back(rendered);
	}
	return out;
}

TEST_CASE("streamed and whole-document parsing agree at EVERY split") {
	// One byte at a time is the interesting case, and so is every size in
	// between: a row, an entity, a comment and a CDATA section each straddle a
	// different boundary depending on the chunk size, and a resumable scanner
	// that gets one of them wrong gets it wrong silently.
	const std::string doc =
		"<root xmlns=\"urn:x:rowset\">"
		"<!-- <row><EVIL>1</EVIL></row> -->"
		"<row><A>one</A><B>Sales &amp; Ops</B></row>"
		"<row><A>two</A><C><![CDATA[<row><X>9</X></row>]]></C><D/></row>"
		"<row><A>three</A><E>&#x1F600;</E></row>"
		"</root>";
	const std::vector<std::string> expected = WholeRows(doc);
	REQUIRE_EQ(expected.size(), 3u);

	for (size_t chunk = 1; chunk <= doc.size(); chunk++) {
		std::vector<std::string> columns;
		const std::vector<std::string> streamed = StreamRows(doc, chunk, columns);
		REQUIRE_EQ(streamed.size(), expected.size());
		for (size_t i = 0; i < expected.size(); i++) {
			REQUIRE_EQ(streamed[i], expected[i]);
		}
	}
}

TEST_CASE("before Finish, an exhausted buffer means 'not yet', not 'no more'") {
	// The distinction is the caller's to make and the parser must not collapse
	// it: a rowset split at a record boundary is incomplete, not empty, and
	// answering "no more rows" there returns a short result with no error.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<root><row><A>1</A>");
	REQUIRE(!parser.Next(row));
	parser.Append("</row>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(row.size(), 1u);
	REQUIRE_EQ(row[0].value, std::string("1"));
	REQUIRE(!parser.Next(row));
	parser.Finish();
	REQUIRE(!parser.Next(row));
}

TEST_CASE("the column union GROWS as rows arrive") {
	// This is why a streaming caller cannot resolve names to indices once. A
	// column null in every row so far is not in the list yet, and probing the
	// first row for a schema is the all-NULL bug.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<row><A>1</A></row>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(parser.columns().size(), 1u);
	parser.Append("<row><A>2</A><LATE>x</LATE></row>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(parser.columns().size(), 2u);
	REQUIRE_EQ(parser.columns()[1], std::string("LATE"));
}

TEST_CASE("an unterminated construct does not rescan EARLIER ones each feed") {
	// NextTag reports how far it skipped so the parser can resume there, so a
	// construct already skipped is not skipped again.
	//
	// This does NOT say the terminator search inside the UNTERMINATED construct
	// is bounded — it is not. Resumption is at that construct's '<', so every
	// feed re-searches the pending region. What bounds it is
	// RowCursor::PARSER_LIMIT, which caps the pending region and turns the cost
	// into a bounded amount of work ending in an error. An earlier version of
	// this case claimed the stronger property in its NAME while asserting only
	// that Next() returns false.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<!-- ");
	for (int i = 0; i < 200; i++) {
		parser.Append("padding padding padding ");
		REQUIRE(!parser.Next(row));
	}
	parser.Append("--><row><A>1</A></row>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(row[0].value, std::string("1"));
	REQUIRE_EQ(parser.columns().size(), 1u);
}

TEST_CASE("a row index past the end is an empty view, not a read off the end") {
	// These indices are derived from a peer's byte stream by way of a caller's
	// arithmetic, so out of range has to be defined rather than undefined.
	const Rowset rs = ParseRowset("<row><A>1</A></row>");
	REQUIRE_EQ(rs.size(), 1u);
	REQUIRE_EQ(rs.Row(1).size(), 0u);
	REQUIRE_EQ(rs.Row(99).size(), 0u);
	REQUIRE(rs.Row(1).Find("A") == nullptr);
	REQUIRE_EQ(rs.ColumnIndex("A"), 0u);
	REQUIRE(rs.ColumnIndex("NOPE") == Rowset::NO_COLUMN);
}

TEST_CASE("a repeated element in one row is last-wins, as the map it replaced was") {
	// Not a preference: the same bytes must not mean two different things before
	// and after the row shape changed.
	const Rowset rs = ParseRowset("<row><A>1</A><A>2</A></row>");
	REQUIRE_EQ(rs.size(), 1u);
	REQUIRE_EQ(rs.Row(0).size(), 1u);
	REQUIRE_EQ(rs.Row(0).At("A"), std::string("2"));
	REQUIRE_EQ(rs.columns.size(), 1u);
}

// --- ColumnMap: the mapping that regressed twice, now reachable --------------

TEST_CASE("a qualified result column maps to the requested bare column") {
	// `EVALUATE 'DimProduct'` returns DimProduct[Colour], not Colour. A scan
	// that looks up the bare name misses every row and returns all-NULL, which
	// is exactly what the first working ATTACH did: DESCRIBE was right and
	// SELECT was a column of nulls.
	const std::vector<std::pair<std::string, int64_t>> requested = {{"ProductKey", 0}, {"Colour", 1}};
	ColumnMap map("DimProduct", requested);
	const std::vector<std::string> discovered = {"DimProduct[Colour]", "DimProduct[ProductKey]"};
	map.Extend(discovered);
	REQUIRE_EQ(map.OutputFor(0), 1);
	REQUIRE_EQ(map.OutputFor(1), 0);
}

TEST_CASE("a bare result column maps too, and so does a bracketed alias") {
	// DISCOVER and DBSCHEMA rowsets carry bare names; an aliased DAX projection
	// returns the alias, which SSAS encodes as _x005B_Colour_x005D_ and the
	// scanner decodes to [Colour]. All three forms have to land on the same
	// output, because which one arrives depends on the query.
	const std::vector<std::pair<std::string, int64_t>> requested = {{"Colour", 0}};
	ColumnMap bare("DimProduct", requested);
	bare.Extend({"Colour"});
	REQUIRE_EQ(bare.OutputFor(0), 0);

	ColumnMap aliased("DimProduct", requested);
	aliased.Extend({"[Colour]"});
	REQUIRE_EQ(aliased.OutputFor(0), 0);
}

TEST_CASE("a column nobody asked for is dropped, not mapped to output 0") {
	const std::vector<std::pair<std::string, int64_t>> requested = {{"Colour", 0}};
	ColumnMap map("DimProduct", requested);
	map.Extend({"DimProduct[Weight]", "DimProduct[Colour]"});
	REQUIRE_EQ(map.OutputFor(0), ColumnMap::NO_OUTPUT);
	REQUIRE_EQ(map.OutputFor(1), 0);
	// Past the end is NO_OUTPUT, not a read off the end: the index comes from a
	// cell in a peer's byte stream.
	REQUIRE_EQ(map.OutputFor(99), ColumnMap::NO_OUTPUT);
}

TEST_CASE("a column that appears only in a LATER row still maps") {
	// The all-NULL bug, in the form it came back as: XMLA omits a null column
	// from a row entirely, so probing row 0 for the schema finds the qualified
	// key absent, falls back to the bare name, and then misses on every row.
	// Extend is therefore called per row and must pick up what row 0 lacked.
	const std::vector<std::pair<std::string, int64_t>> requested = {{"ProductKey", 0}, {"Colour", 1}};
	ColumnMap map("DimProduct", requested);
	map.Extend({"DimProduct[ProductKey]"});
	REQUIRE_EQ(map.size(), 1u);
	REQUIRE_EQ(map.OutputFor(0), 0);
	map.Extend({"DimProduct[ProductKey]", "DimProduct[Colour]"});
	REQUIRE_EQ(map.size(), 2u);
	REQUIRE_EQ(map.OutputFor(1), 1);
}

TEST_CASE("the same mapping, driven from a parsed rowset end to end") {
	// The two halves together: the parser discovers a column only on the second
	// row, and the map still routes it. This is the whole regression in one
	// case, and it is now hermetic.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<row><DimProduct_x005B_ProductKey_x005D_>1</DimProduct_x005B_ProductKey_x005D_></row>");
	parser.Append(
		"<row><DimProduct_x005B_ProductKey_x005D_>2</DimProduct_x005B_ProductKey_x005D_>"
		"<DimProduct_x005B_Colour_x005D_>Red</DimProduct_x005B_Colour_x005D_></row>");
	parser.Finish();

	const std::vector<std::pair<std::string, int64_t>> requested = {{"ProductKey", 0}, {"Colour", 1}};
	ColumnMap map("DimProduct", requested);
	std::vector<std::string> colour_by_row;
	while (parser.Next(row)) {
		std::string colour = "<null>";
		map.Extend(parser.columns());
		for (const auto &cell : row) {
			if (map.OutputFor(cell.column) == 1) {
				colour = cell.value;
			}
		}
		colour_by_row.push_back(colour);
	}
	REQUIRE_EQ(colour_by_row.size(), 2u);
	REQUIRE_EQ(colour_by_row[0], std::string("<null>"));
	REQUIRE_EQ(colour_by_row[1], std::string("Red"));
}

TEST_CASE("an output position is what the caller SAID, not the list index") {
	// A scan skips a column id with no server counterpart — a row id, or the
	// EMPTY placeholder count(*) asks for — so its names compact while its
	// output positions do not. Deriving the position from list order mapped the
	// first real column after a skip to output 0 instead of 1, and the symptom
	// is a requested column arriving all NULL with no error.
	const std::vector<std::pair<std::string, int64_t>> requested = {{"Colour", 1}};
	ColumnMap map("DimProduct", requested);
	map.Extend({"DimProduct[Colour]"});
	REQUIRE_EQ(map.OutputFor(0), 1);
}

TEST_CASE("compaction reclaims consumed bytes INSIDE an open row") {
	// A peer that opens a <row> and sends endless children never closes it, so
	// compaction that gives up while a row is open has nothing to reclaim for
	// the rest of the document — and a cap on the UNCONSUMED bytes does not see
	// it, because those stay small while the buffer grows. buffered() is the
	// observable: it must not grow with the number of children consumed.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<root><row>");
	REQUIRE(!parser.Next(row));
	for (int i = 0; i < 500; i++) {
		parser.Append("<A>0123456789012345678901234567890123456789</A>");
		REQUIRE(!parser.Next(row));
	}
	// One child's worth, not five hundred.
	REQUIRE(parser.buffered() < 512u);
	parser.Append("</row></root>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(row.size(), 1u);
}

TEST_CASE("a pending value straddling a compaction survives it") {
	// Compaction inside a row shifts pending_from_, and getting that wrong reads
	// the value from the wrong offset — silently, because any offset yields SOME
	// text.
	RowStreamParser parser;
	std::vector<Cell> row;
	parser.Append("<row><A>1</A><B>the value");
	REQUIRE(!parser.Next(row));
	parser.Append(" continues</B></row>");
	REQUIRE(parser.Next(row));
	REQUIRE_EQ(row.size(), 2u);
	REQUIRE_EQ(parser.columns()[row[0].column], std::string("A"));
	REQUIRE_EQ(row[0].value, std::string("1"));
	REQUIRE_EQ(parser.columns()[row[1].column], std::string("B"));
	REQUIRE_EQ(row[1].value, std::string("the value continues"));
}

TEST_CASE("a row index of SIZE_MAX is an empty view, not an overflowed check") {
	// `i + 1 >= row_starts.size()` overflows: for SIZE_MAX it is 0, which is not
	// >= a size that is always at least 1, so the guard passed and
	// row_starts[SIZE_MAX] was read.
	const Rowset rs = ParseRowset("<row><A>1</A></row>");
	REQUIRE_EQ(rs.Row(static_cast<size_t>(-1)).size(), 0u);
	REQUIRE(rs.Row(static_cast<size_t>(-1)).Find("A") == nullptr);
	REQUIRE_EQ(rs.Row(static_cast<size_t>(-2)).size(), 0u);
}
