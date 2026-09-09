//===----------------------------------------------------------------------===//
// The spike: connect, negotiate, authenticate, seal a Discover, print rows.
//
// This exists to prove the risky part end to end BEFORE any DuckDB integration.
// No table function and no ATTACH path is worth writing until this returns rows
// from a real instance.
//
// It prints NOTHING identifying: no host, no port, no principal, no realm, no
// token, no SPN (constitution I). Configuration comes from the environment, so
// nothing lands in a shell history file either.
//
//   XMLA_TEST_HOST       required
//   XMLA_TEST_PORT       required - pinned; there is no redirector (research D9)
//   XMLA_TEST_MECHANISM  ntlm | kerberos | negotiate   (default kerberos)
//   XMLA_TEST_USER       principal; empty means the ambient identity
//   XMLA_TEST_PASSWORD   standalone NTLM only; never stored, never printed
//   XMLA_TEST_CATALOG    optional, for the metadata requests that take one
//   XMLA_TEST_SPN        optional full SPN override
//===----------------------------------------------------------------------===//
#include "xmla/client.hpp"
#include "xmla/errors.hpp"
#include "xmla/gss_context.hpp"
#include "xmla/redact.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace xmla;

namespace {

std::string Env(const char *name, const char *fallback = "") {
	const char *v = std::getenv(name);
	return v ? std::string(v) : std::string(fallback);
}

//! Row VALUES are scrubbed before printing, not just error text.
//!
//! This is not theoretical. DISCOVER_DATASOURCES answers with the instance's own
//! DataSourceName, which on a standalone box is MACHINE\\INSTANCE - so the first
//! run of this probe printed a machine name straight to the terminal. Anything
//! printed here can be pasted into an issue, so the scrubber runs on output, not
//! only on faults (constitution I).
void PrintRowset(const Scrubber &scrub, const char *label, const Rowset &rs, size_t max_rows) {
	std::printf("\n%s: %zu row(s), %zu column(s)\n", label, rs.size(), rs.columns.size());
	if (rs.columns.empty()) {
		return;
	}
	std::printf("  columns:");
	for (size_t i = 0; i < rs.columns.size() && i < 12; i++) {
		std::printf(" %s", rs.columns[i].c_str());
	}
	if (rs.columns.size() > 12) {
		std::printf(" ... (+%zu)", rs.columns.size() - 12);
	}
	std::printf("\n");
	for (size_t r = 0; r < rs.rows.size() && r < max_rows; r++) {
		std::printf("  row %zu:", r);
		size_t shown = 0;
		for (const auto &col : rs.columns) {
			const auto it = rs.rows[r].find(col);
			if (it == rs.rows[r].end()) {
				continue;
			}
			std::printf(" %s=%s", col.c_str(), scrub(it->second).c_str());
			if (++shown >= 4) {
				break;
			}
		}
		std::printf("\n");
	}
}

}  // namespace

int main() {
	const std::string host = Env("XMLA_TEST_HOST");
	const std::string port_s = Env("XMLA_TEST_PORT");
	if (host.empty() || port_s.empty()) {
		std::fprintf(stderr, "set XMLA_TEST_HOST and XMLA_TEST_PORT (see .env.example)\n");
		return 2;
	}

	// atoi truncates silently, and ConnectionTarget refuses a DEFAULT port
	// precisely because "guessing wrong presents as a hang rather than as an
	// error". Quietly turning 65538 into port 2 reintroduces exactly that: the
	// probe would report a connection failure against a port the operator never
	// named.
	char *end = nullptr;
	const unsigned long parsed = std::strtoul(port_s.c_str(), &end, 10);
	if (end == port_s.c_str() || (end && *end != '\0') || parsed < 1 || parsed > 65535) {
		std::fprintf(stderr, "XMLA_TEST_PORT must be a number in 1..65535\n");
		return 2;
	}

	ConnectionTarget target;
	target.host = host;
	target.port = static_cast<uint16_t>(parsed);
	target.timeout_seconds = 30.0;

	Credential credential;
	credential.mechanism = Env("XMLA_TEST_MECHANISM", "kerberos");
	credential.principal = Env("XMLA_TEST_USER");
	credential.spn_override = Env("XMLA_TEST_SPN");

	const std::string password = Env("XMLA_TEST_PASSWORD");
	const std::string catalog = Env("XMLA_TEST_CATALOG");

	// The mechanism is the only piece of configuration safe to echo: it names an
	// algorithm, not an identity.
	std::printf("xmla probe: mechanism=%s, ambient identity=%s\n", credential.mechanism.c_str(),
				credential.principal.empty() ? "yes" : "no");

	Session session(target, credential);
	try {
		std::unique_ptr<GssContext> context = GssContext::Create(credential, target.host, target.port, password);
		std::printf("security context created; running the handshake\n");
		session.Open(nullptr, std::move(context));
		std::printf("authenticated. sealing with: %s\n", session.SealDescription().c_str());

		// The scrubber knows the two literals we were given; the patterns catch
		// the shapes we were not, which is how the machine name in
		// DISCOVER_DATASOURCES gets caught.
		const Scrubber scrub(host, credential.principal);

		// The milestone's own acceptance check.
		const Rowset datasources = session.Discover("DISCOVER_DATASOURCES");
		PrintRowset(scrub, "DISCOVER_DATASOURCES", datasources, 3);

		const Rowset catalogs = session.Discover("DBSCHEMA_CATALOGS");
		PrintRowset(scrub, "DBSCHEMA_CATALOGS", catalogs, 10);

		if (!catalog.empty()) {
			PrintRowset(scrub, "DBSCHEMA_TABLES", session.Discover("DBSCHEMA_TABLES", {}, catalog), 5);
			// The response that exercises every splitting threshold at once.
			const Rowset columns = session.Discover("DBSCHEMA_COLUMNS", {}, catalog);
			PrintRowset(scrub, "DBSCHEMA_COLUMNS", columns, 3);
			std::printf("\nDBSCHEMA_COLUMNS returned %zu rows - past every splitting threshold.\n", columns.size());
		} else {
			std::printf("\nset XMLA_TEST_CATALOG to also exercise DBSCHEMA_TABLES/COLUMNS\n");
		}

		session.Close();
		std::printf("\nPROBE OK\n");
		return 0;
	} catch (const XmlaError &e) {
		// e.what() is already scrubbed where it carries server text.
		std::fprintf(stderr, "\nPROBE FAILED (%s)\n", e.what());
		return 1;
	} catch (const std::exception &e) {
		std::fprintf(stderr, "\nPROBE FAILED (unexpected): %s\n", e.what());
		return 1;
	}
}
