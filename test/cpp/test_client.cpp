#include "fake_server.hpp"
#include "harness.hpp"
#include "xmla/auth.hpp"
#include "xmla/client.hpp"
#include "xmla/errors.hpp"

#include <memory>
#include <string>
#include <vector>

using namespace xmla;

static const char *kAuthResponse =
	"<Envelope><Body><AuthenticateResponse "
	"xmlns=\"http://schemas.microsoft.com/analysisservices/2003/ext\">"
	"<SspiHandshake>AQID</SspiHandshake></AuthenticateResponse></Body></Envelope>";

static std::string RowsetDocument(int rows) {
	std::string doc =
		"<Envelope><Body><DiscoverResponse><return>"
		"<root xmlns=\"urn:schemas-microsoft-com:xml-analysis:rowset\">"
		"<Session SessionId=\"SID-42\"/>";
	for (int i = 0; i < rows; i++) {
		doc += "<row><CATALOG_NAME>Catalog " + std::to_string(i) +
			   "</CATALOG_NAME><DESCRIPTION>a description long enough to matter</DESCRIPTION></row>";
	}
	doc += "</root></return></DiscoverResponse></Body></Envelope>";
	return doc;
}

static ConnectionTarget Target() {
	ConnectionTarget t;
	t.host = "instance.invalid";
	t.port = 2383;
	return t;
}

TEST_CASE("a port is required; there is no default and no redirector") {
	ConnectionTarget t;
	t.host = "instance.invalid";
	t.port = 0;
	REQUIRE_THROWS_EXACTLY(ConnectionError, t.Validate());
	t.port = 2383;
	t.timeout_seconds = 0;
	REQUIRE_THROWS_EXACTLY(ConnectionError, t.Validate());
}

TEST_CASE("a session opens, authenticates, and returns rows") {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(2), 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	REQUIRE(session.state() == State::AUTHENTICATED);

	const Rowset rs = session.Discover("DBSCHEMA_CATALOGS");
	REQUIRE_EQ(rs.size(), 2u);
	REQUIRE_EQ(rs.Row(0).At("CATALOG_NAME"), std::string("Catalog 0"));
}

TEST_CASE("a request before authentication is refused as Authentication") {
	Session session(Target(), Credential());
	REQUIRE_THROWS_EXACTLY(AuthenticationError, session.Discover("DBSCHEMA_CATALOGS"));
}

TEST_CASE("the SessionId is captured and carried on every later request") {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(1), 0));
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(1), 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	session.Discover("DBSCHEMA_CATALOGS");
	const size_t after_first = chan->sent().size();
	session.Discover("DBSCHEMA_TABLES");

	// The second request must carry the id, not another BeginSession. Without
	// this the client re-sends BeginSession forever and opens a new server-side
	// session per request.
	const std::string second(chan->sent().begin() + static_cast<long>(after_first), chan->sent().end());
	// The body is sealed, so decrypt the way the peer would.
	FakeSealProvider reader(16, 2888);
	const Bytes second_bytes(second.begin(), second.end());
	const dime::DecodedMessage msg = dime::DecodeMessageAt(second_bytes.data(), second_bytes.size(), 0);
	const Bytes plain = sealing::UnsealMessage(reader, msg.payload);
	const std::string request(plain.begin(), plain.end());
	REQUIRE(request.find("SessionId=\"SID-42\"") != std::string::npos);
	REQUIRE(request.find("BeginSession") == std::string::npos);
}

TEST_CASE("the FIRST record leaves NEGO clear and later ones set it") {
	// A negotiation bit set on record one is silently fatal: the server closes
	// the connection with no error and logs nothing.
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(1), 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	REQUIRE_EQ(chan->sent()[dime::HEADER_LEN], 0);
	const size_t after_auth = chan->sent().size();
	session.Discover("DBSCHEMA_CATALOGS");
	REQUIRE_EQ(chan->sent()[after_auth + dime::HEADER_LEN], dime::OPT_NEGO);
}

TEST_CASE("a fault during the handshake is Authentication, not Server") {
	const char *denied =
		"<Envelope><Body><Fault><faultcode>XMLAnalysisError</faultcode>"
		"<faultstring>Logon failure</faultstring></Fault></Body></Envelope>";
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(denied, 0));

	Session session(Target(), Credential());
	REQUIRE_THROWS_EXACTLY(AuthenticationError,
						   session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888))));
	REQUIRE(session.state() == State::FAILED);
}

TEST_CASE("a permission fault is Authorization, not Server") {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	const char *denied =
		"<Envelope><Body><Fault><faultcode>XMLAnalysisError</faultcode>"
		"<faultstring>The user does not have access to the database.</faultstring>"
		"</Fault></Body></Envelope>";
	chan->Queue(SealedResponseWire(server_side, denied, 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	REQUIRE_THROWS_EXACTLY(AuthorizationError, session.Discover("DBSCHEMA_CATALOGS"));
}

TEST_CASE("a permission fault is classified whatever its casing") {
	// The existing classification test uses "The user does not have access to the
	// database.", whose text already matches a kDeniedMarkers entry verbatim — so
	// an IDENTITY fold passes it, and the ASCII ToLower it exercises could stop
	// folding without any test noticing. That is the same shape as the defect
	// this whole branch exists to prevent.
	//
	// These faults only classify as AuthorizationError if the fold actually runs.
	const char *denied[] = {
		"Permission Denied for this operation.",
		"The caller is Not Authorized.",
		"ACCESS IS DENIED",
		"The user DOES NOT HAVE ACCESS to the database.",
	};
	for (const char *text : denied) {
		auto chan = std::make_shared<BytesChannel>();
		chan->Queue(PlainResponseWire(kAuthResponse, 0));
		FakeSealProvider server_side(16, 2888);
		const std::string fault = std::string(
									  "<Envelope><Body><Fault>"
									  "<faultcode>XMLAnalysisError</faultcode><faultstring>") +
								  text + "</faultstring></Fault></Body></Envelope>";
		chan->Queue(SealedResponseWire(server_side, fault, 0));

		Session session(Target(), Credential());
		session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
		REQUIRE_THROWS_EXACTLY(AuthorizationError, session.Discover("DBSCHEMA_CATALOGS"));
	}
}

TEST_CASE("a response that does not decrypt to XML raises, rather than parsing to empty") {
	// An empty rowset is a meaningful answer, so a cipher-layer failure must not
	// be indistinguishable from one.
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	chan->Queue(SealedResponseWire(server_side, "not xml at all, just bytes", 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	REQUIRE_THROWS_EXACTLY(ProtocolError, session.Discover("DBSCHEMA_CATALOGS"));
}

TEST_CASE("an empty rowset is returned as zero rows, not as an error") {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(16, 2888);
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(0), 0));

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 2888)));
	const Rowset rs = session.Discover("DBSCHEMA_CATALOGS");
	REQUIRE_EQ(rs.size(), 0u);
}

TEST_CASE("a multi-leg handshake completes and only then seals") {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	FakeSealProvider server_side(60, 2888);
	chan->Queue(SealedResponseWire(server_side, RowsetDocument(1), 0));

	Session session(Target(), Credential());
	auto ctx = std::unique_ptr<FakeGssContext>(new FakeGssContext(2, 60, 2888));
	FakeGssContext *raw = ctx.get();
	session.Open(chan, std::move(ctx));
	REQUIRE_EQ(raw->steps(), 2);
	REQUIRE_EQ(session.Discover("DBSCHEMA_CATALOGS").size(), 1u);
}

TEST_CASE("a handshake that never completes is bounded") {
	auto chan = std::make_shared<BytesChannel>();
	for (int i = 0; i < 20; i++) {
		chan->Queue(PlainResponseWire(kAuthResponse, 0));
	}
	Session session(Target(), Credential());
	REQUIRE_THROWS_EXACTLY(AuthenticationError,
						   session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(99, 16, 2888))));
}

//===----------------------------------------------------------------------===//
// T-031: all three splits at once.
//===----------------------------------------------------------------------===//

TEST_CASE("T-031: sealed frames, DIME records and short reads compose") {
	// Three independent splits apply to one message at three layers. The
	// reference implementation only ever hit the composition through a 1366-row
	// response that happened to trigger two of the three; this pins all three.
	//
	// 400 rows is ~40 KB, which at these settings is ~500 sealed frames inside
	// ~130 DIME records delivered over ~1300 reads.
	const std::string document = RowsetDocument(400);

	const size_t chunk_bytes = 80;	  // layer 1: many sealed frames per message
	const size_t record_bytes = 300;  // layer 2: many DIME records per message
	const size_t read_bytes = 32;	  // layer 3: many socket reads per record

	FakeSealProvider server_side(60, chunk_bytes);
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, record_bytes));
	chan->Queue(SealedResponseWire(server_side, document, record_bytes));
	chan->SetChunkSize(read_bytes);

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 60, chunk_bytes)));

	const Rowset rs = session.Discover("DBSCHEMA_CATALOGS");
	REQUIRE_EQ(rs.size(), 400u);
	// Not just the count: the first, last and a middle row, so a reassembly that
	// drops or duplicates a chunk in the middle cannot pass.
	REQUIRE_EQ(rs.Row(0).At("CATALOG_NAME"), std::string("Catalog 0"));
	REQUIRE_EQ(rs.Row(200).At("CATALOG_NAME"), std::string("Catalog 200"));
	REQUIRE_EQ(rs.Row(399).At("CATALOG_NAME"), std::string("Catalog 399"));
	REQUIRE_EQ(rs.Row(399).At("DESCRIPTION"), std::string("a description long enough to matter"));
	// The frames really were split: one BOM frame plus ceil(len/chunk).
	REQUIRE(server_side.frames_sealed() > 100u);
}

TEST_CASE("T-031: the same composition holds at every measured token size") {
	// Token size varies by mechanism and, for Kerberos, by session-key enctype.
	// A reassembly that quietly assumed one would pass the case above and fail
	// against a real AES session.
	const size_t token_sizes[] = {16, 60, 64, 72};
	for (size_t token_len : token_sizes) {
		const std::string document = RowsetDocument(50);
		FakeSealProvider server_side(token_len, 64);
		auto chan = std::make_shared<BytesChannel>();
		chan->Queue(PlainResponseWire(kAuthResponse, 128));
		chan->Queue(SealedResponseWire(server_side, document, 128));
		chan->SetChunkSize(17);	 // deliberately not a divisor of anything

		Session session(Target(), Credential());
		session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, token_len, 64)));
		REQUIRE_EQ(session.Discover("DBSCHEMA_CATALOGS").size(), 50u);
	}
}

TEST_CASE("base64 round-trips, and rejects what it should") {
	for (size_t n = 0; n < 40; n++) {
		Bytes in(n);
		for (size_t i = 0; i < n; i++) {
			in[i] = static_cast<uint8_t>(i * 7 + 3);
		}
		Bytes out;
		REQUIRE(auth::Base64Decode(auth::Base64Encode(in), out));
		REQUIRE_EQ(out, in);
	}
	Bytes out;
	REQUIRE(!auth::Base64Decode("!!!!", out));
	// Padding must be terminal: data after it is two encodings concatenated,
	// which would decode to something the sender never wrote.
	REQUIRE(!auth::Base64Decode("QQ==QQ==", out));
}

// --- the streaming cursor (T-042) -------------------------------------------

static std::string EvaluateDocument(int rows) {
	std::string doc =
		"<Envelope><Body><ExecuteResponse><return>"
		"<root xmlns=\"urn:schemas-microsoft-com:xml-analysis:rowset\">"
		"<Session SessionId=\"SID-42\"/>";
	for (int i = 0; i < rows; i++) {
		doc += "<row><T_x005B_A_x005D_>" + std::to_string(i) + "</T_x005B_A_x005D_></row>";
	}
	doc += "</root></return></ExecuteResponse></Body></Envelope>";
	return doc;
}

static std::shared_ptr<BytesChannel> AuthenticatedChannel(FakeSealProvider &server_side, const std::string &document,
														  size_t record_bytes, size_t read_bytes) {
	auto chan = std::make_shared<BytesChannel>();
	chan->Queue(PlainResponseWire(kAuthResponse, 0));
	chan->Queue(SealedResponseWire(server_side, document, record_bytes));
	if (read_bytes) {
		chan->SetChunkSize(read_bytes);
	}
	return chan;
}

TEST_CASE("a cursor yields the same rows as Execute, across record and read splits") {
	// The three splitting layers compose (see fake_server.hpp), and a resumable
	// reader is exactly where they stop being independent.
	FakeSealProvider server_side(16, 512);
	auto chan = AuthenticatedChannel(server_side, EvaluateDocument(50), 200, 37);

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 512)));

	auto cursor = session.ExecuteCursor("EVALUATE 'T'");
	std::vector<Cell> row;
	int seen = 0;
	while (cursor->Next(row)) {
		REQUIRE_EQ(row.size(), 1u);
		REQUIRE_EQ(cursor->columns()[row[0].column], std::string("T[A]"));
		REQUIRE_EQ(row[0].value, std::to_string(seen));
		seen++;
	}
	REQUIRE_EQ(seen, 50);
	REQUIRE(cursor->complete());
}

TEST_CASE("a cursor abandoned early leaves the rest of the response UNREAD") {
	// This is the whole reason the cursor exists. DuckDB v2.0 passes no limit to
	// a table function, so a `LIMIT 5` scan cannot ask the server for five rows;
	// what it can do is stop reading, and that only saves anything if the
	// remaining bytes are never pulled off the wire.
	FakeSealProvider server_side(16, 512);
	auto chan = AuthenticatedChannel(server_side, EvaluateDocument(400), 256, 64);

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 512)));

	{
		auto cursor = session.ExecuteCursor("EVALUATE 'T'");
		std::vector<Cell> row;
		REQUIRE(cursor->Next(row));
		REQUIRE_EQ(row[0].value, std::string("0"));
		REQUIRE(!cursor->complete());
		REQUIRE(chan->unread() > 0);
	}
	// Still unread after the cursor went away: it abandoned the message rather
	// than draining it.
	REQUIRE(chan->unread() > 0);
	// And the session is unusable, deliberately: half a DIME message has been
	// taken off the socket and there is no way back to a record boundary.
	REQUIRE(session.state() == State::FAILED);
	REQUIRE_THROWS_EXACTLY(AuthenticationError, session.Discover("DBSCHEMA_CATALOGS"));
}

TEST_CASE("a fault in a streamed response is raised, not returned as zero rows") {
	// An empty rowset is a MEANINGFUL answer in this layer, so a refusal that
	// arrives looking like one is a silent wrong answer.
	const char *fault =
		"<soap:Envelope><soap:Body><soap:Fault>"
		"<faultcode>XMLAnalysisError.0xc10e0002</faultcode>"
		"<faultstring>The user does not have permission.</faultstring>"
		"</soap:Fault></soap:Body></soap:Envelope>";
	FakeSealProvider server_side(16, 512);
	auto chan = AuthenticatedChannel(server_side, fault, 0, 0);

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 512)));

	auto cursor = session.ExecuteCursor("EVALUATE 'T'");
	std::vector<Cell> row;
	REQUIRE_THROWS_EXACTLY(AuthorizationError, cursor->Next(row));
}

TEST_CASE("a cursor refuses a statement that is not read-only, before any request") {
	// The guard is on the STATEMENT, so it does not care how the answer is read.
	Session session(Target(), Credential());
	REQUIRE_THROWS_EXACTLY(AuthenticationError, session.ExecuteCursor("UPDATE CUBE [S] SET (m) = 0"));
}

TEST_CASE("a response that does not decrypt to XML is refused, streaming too") {
	// The likeliest failure of a cipher layer produces plausible emptiness, and
	// zero rows is a legitimate answer here — so the shape is checked.
	FakeSealProvider server_side(16, 512);
	auto chan = AuthenticatedChannel(server_side, "not xml at all", 0, 0);

	Session session(Target(), Credential());
	session.Open(chan, std::unique_ptr<GssContext>(new FakeGssContext(1, 16, 512)));

	auto cursor = session.ExecuteCursor("EVALUATE 'T'");
	std::vector<Cell> row;
	REQUIRE_THROWS_EXACTLY(ProtocolError, cursor->Next(row));
}
