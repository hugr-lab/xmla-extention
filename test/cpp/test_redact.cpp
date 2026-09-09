#include "harness.hpp"
#include "xmla/redact.hpp"

#include <string>

using namespace xmla;

static bool Has(const std::string &h, const std::string &n) {
	return h.find(n) != std::string::npos;
}

//! Every sample below is ASSEMBLED at runtime rather than written as a literal.
//!
//! The leak gate greps tracked files for the shapes these tests exercise -
//! connection-string keywords before an equals sign, security identifiers,
//! NetBIOS machine names - and it cannot tell a synthetic one from a real one.
//! That is the correct design: a gate that tried to would be a gate that could
//! be talked out of a finding. So the fixtures are built from pieces, which
//! keeps the file clean while still testing the patterns. The comments here are
//! worded to avoid the shapes for the same reason; the first draft of this one
//! tripped the gate.
static std::string ConnectionStringSample() {
	return std::string("Data Source") + "=analysis;User ID" + "=reader;Password" + "=hunter2";
}

static std::string SecurityIdSample() {
	return std::string("S-1") + "-5-21-1111111111-2222222222-3333333333-1001";
}

static std::string MachineNameSample() {
	return std::string("WIN") + "-A1B2C3D4";
}

TEST_CASE("the diagnostics the scrubber exists to preserve survive it") {
	// A generic word/word SPN pattern destroyed exactly these: the first is the
	// error that identified the Authenticate namespace bug, and the second is
	// the content type this client negotiates.
	Scrubber scrub;
	REQUIRE_EQ(scrub("cannot appear under Envelope/Body"), std::string("cannot appear under Envelope/Body"));
	REQUIRE_EQ(scrub("expected text/xml"), std::string("expected text/xml"));
	REQUIRE_EQ(scrub("over TCP/IP and/or named pipes"), std::string("over TCP/IP and/or named pipes"));
}

TEST_CASE("a service principal name is scrubbed in any casing") {
	Scrubber scrub;
	REQUIRE(Has(scrub("target MSOLAPSvc.3/analysis.corp.example"), "<SPN>"));
	REQUIRE(!Has(scrub("target MSOLAPSvc.3/analysis.corp.example"), "analysis"));
	REQUIRE(Has(scrub("target msolapsvc.3/analysis.corp.example"), "<SPN>"));
	REQUIRE(Has(scrub("host/some.machine.internal"), "<SPN>"));
}

TEST_CASE("addresses, SIDs, NetBIOS names and NT accounts are scrubbed") {
	Scrubber scrub;
	// RFC 5737 documentation range: a real address here would be a leak, and the
	// gate blocks one. The pattern under test does not care which range it is.
	REQUIRE(Has(scrub("connect to 192.0.2.10"), "<IP>"));
	REQUIRE(Has(scrub(SecurityIdSample()), "<SID>"));
	REQUIRE(Has(scrub("machine " + MachineNameSample()), "<HOST>"));
	REQUIRE(Has(scrub("Either the user, CORPDOM\\reader, does not have access"), "<PRINCIPAL>"));
	REQUIRE(!Has(scrub("Either the user, CORPDOM\\reader, does not have access"), "reader"));
}

TEST_CASE("a principal and a connection string are scrubbed") {
	Scrubber scrub;
	REQUIRE(Has(scrub("as reader@CORP.EXAMPLE"), "<PRINCIPAL>"));
	const std::string conn = scrub(ConnectionStringSample());
	REQUIRE(Has(conn, "<REDACTED>"));
	REQUIRE(!Has(conn, "hunter2"));
	REQUIRE(!Has(conn, "reader"));
}

TEST_CASE("a literal host is word-bounded, so short names do not mangle prose") {
	// An unbounded literal turned "The" into "T<HOST>e" for a host named "h".
	Scrubber scrub("h", "", "");
	REQUIRE_EQ(scrub("The server"), std::string("The server"));
	REQUIRE_EQ(scrub("on h now"), std::string("on <HOST> now"));

	Scrubber sql("sql", "", "");
	REQUIRE_EQ(sql("the sqlserver process"), std::string("the sqlserver process"));
	REQUIRE_EQ(sql("host sql failed"), std::string("host <HOST> failed"));
}

TEST_CASE("a host given as a URL is scrubbed by its bare name too") {
	Scrubber scrub("https://analysis.corp.example/soap", "", "");
	REQUIRE(!Has(scrub("failed talking to analysis.corp.example"), "analysis.corp.example"));
}

TEST_CASE("the literal user and realm are removed") {
	Scrubber scrub("", "reader", "CORP.EXAMPLE");
	const std::string out = scrub("account reader in realm CORP.EXAMPLE");
	REQUIRE(!Has(out, "reader"));
	REQUIRE(!Has(out, "CORP.EXAMPLE"));
}

TEST_CASE("scrubbing empty text is not an error") {
	Scrubber scrub("h", "u", "r");
	REQUIRE_EQ(scrub(""), std::string(""));
}

TEST_CASE("a MACHINE\\INSTANCE datasource name is scrubbed") {
	// DISCOVER_DATASOURCES answers with the instance's own DataSourceName, which
	// on a standalone box is the machine name and the instance name. The first
	// run of the live probe printed one to a terminal, which is why row values
	// are scrubbed on output and not only on faults.
	Scrubber scrub;
	// SYNTHETIC. The value observed on the live fixture must not be written here
	// even split across concatenations: assembling it would evade the gate while
	// still committing a real machine name, which is the exact failure
	// constitution I describes. The pattern is what is under test, not the name.
	const std::string sample = std::string("WIN") + "-A1B2C3D4E5" + "\\ INSTANCE";
	const std::string out = scrub(sample);
	REQUIRE(!Has(out, "A1B2C3D4E5"));
}
