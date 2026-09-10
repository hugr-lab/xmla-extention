//===----------------------------------------------------------------------===//
// The one ATTACH behaviour sqllogictest cannot reach.
//
// `access_mode` is a startup-only setting: `SET access_mode = 'read_write'` is
// refused once the database is running, so no .test file can put a session in
// that state. Every real client can — python `duckdb.connect(config={...})`,
// JDBC `duckdb.read_only=false`, `duckdb_open_ext` — and that is exactly the
// configuration in which this extension once refused a plain ATTACH while
// naming an option the user never wrote:
//
//     ATTACH 'host=… port=…' AS aw (TYPE xmla)
//     -> xmla: an Analysis Services attachment is read-only;
//        remove READ_ONLY false from the ATTACH options
//
// The cause was reading AttachOptions::access_mode, which is SEEDED from the
// session's DBConfig and only overwritten when the statement carried a
// read-only option. The fix reads the statement's own options. This pins it, so
// a revert fails a check rather than a manual retest nobody repeats.
//
// Server-free: ATTACH deliberately contacts nothing.
//===----------------------------------------------------------------------===//
#include "duckdb.h"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int failures = 0;

void Check(bool ok, const char *what) {
	std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
	if (!ok) {
		failures++;
	}
}

//! Run a statement; return the error message, or an empty string on success.
std::string Run(duckdb_connection con, const std::string &sql) {
	duckdb_result result;
	std::string error;
	if (duckdb_query(con, sql.c_str(), &result) == DuckDBError) {
		const char *message = duckdb_result_error(&result);
		error = message ? message : "unknown error";
		if (error.empty()) {
			error = "unknown error";
		}
	}
	duckdb_destroy_result(&result);
	return error;
}

//! First column of the first row, as a string. Empty when there is no row.
std::string Scalar(duckdb_connection con, const std::string &sql) {
	duckdb_result result;
	if (duckdb_query(con, sql.c_str(), &result) == DuckDBError) {
		duckdb_destroy_result(&result);
		return std::string();
	}
	std::string out;
	char *value = duckdb_value_varchar(&result, 0, 0);
	if (value) {
		out = value;
		duckdb_free(value);
	}
	duckdb_destroy_result(&result);
	return out;
}

}  // namespace

int main(int argc, char **argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: %s <path to xmla.duckdb_extension>\n", argv[0]);
		return 2;
	}
	const std::string extension = argv[1];

	duckdb_config config;
	if (duckdb_create_config(&config) == DuckDBError) {
		std::fprintf(stderr, "could not create a config\n");
		return 2;
	}
	// The whole point of this file. Not reachable from SQL.
	duckdb_set_config(config, "access_mode", "read_write");
	duckdb_set_config(config, "allow_unsigned_extensions", "true");

	duckdb_database db;
	char *open_error = nullptr;
	// In memory: this test writes nothing and must not leave a file behind.
	if (duckdb_open_ext(":memory:", &db, config, &open_error) == DuckDBError) {
		std::fprintf(stderr, "could not open the database: %s\n", open_error ? open_error : "unknown");
		duckdb_free(open_error);
		duckdb_destroy_config(&config);
		return 2;
	}
	duckdb_destroy_config(&config);

	duckdb_connection con;
	if (duckdb_connect(db, &con) == DuckDBError) {
		std::fprintf(stderr, "could not connect\n");
		duckdb_close(&db);
		return 2;
	}

	// What this LOAD does and does not prove, since it is easy to over-read.
	//
	// extension_config.cmake registers xmla WITHOUT DONT_LINK, so it is linked
	// into libduckdb and registered at open time: `duckdb_extensions()` reports
	// its install_path as "(BUILT-IN)", and the ATTACH checks below therefore
	// exercise THAT copy, not the .duckdb_extension file. What the LOAD does
	// prove is that the built artifact exists and is accepted — verified by
	// passing a path that does not exist, which fails here with
	// 'Extension "..." not found' rather than being ignored.
	const std::string load_error = Run(con, "LOAD '" + extension + "'");
	if (!load_error.empty()) {
		std::fprintf(stderr, "could not load the extension: %s\n", load_error.c_str());
		duckdb_disconnect(&con);
		duckdb_close(&db);
		return 2;
	}
	if (Scalar(con, "SELECT count(*) FROM duckdb_extensions() WHERE extension_name = 'xmla' AND loaded") != "1") {
		std::fprintf(stderr, "the xmla extension is not loaded\n");
		duckdb_disconnect(&con);
		duckdb_close(&db);
		return 2;
	}

	std::printf("access_mode=read_write, which no .test file can produce:\n");

	// A plain ATTACH carries no read-only option, so it is not a request for
	// anything and must succeed.
	const std::string plain = Run(con, "ATTACH 'host=example.invalid port=2383' AS plain (TYPE xmla)");
	Check(plain.empty(), "a plain ATTACH is accepted, not refused for an option nobody wrote");
	if (!plain.empty()) {
		std::printf("       %s\n", plain.c_str());
	}

	// ... and it is still read-only, which is the guarantee the refusal exists
	// to protect. Accepting the ATTACH must not have accepted read-write.
	Check(Scalar(con, "SELECT readonly FROM duckdb_databases() WHERE database_name = 'plain'") == "true",
		  "the attachment is read-only even though the session is read_write");

	// An EXPLICIT request is still refused. The fix must not have turned the
	// refusal off, only made it read the right thing.
	const std::string explicit_rw =
		Run(con, "ATTACH 'host=example.invalid port=2383' AS rw (TYPE xmla, READ_ONLY false)");
	Check(explicit_rw.find("read-only") != std::string::npos, "READ_ONLY false is still refused");
	const std::string explicit_rw2 =
		Run(con, "ATTACH 'host=example.invalid port=2383' AS rw2 (TYPE xmla, READ_WRITE true)");
	Check(explicit_rw2.find("read-only") != std::string::npos, "READ_WRITE true is still refused");

	duckdb_disconnect(&con);
	duckdb_close(&db);

	std::printf("%d check(s) failed\n", failures);
	return failures == 0 ? 0 : 1;
}
