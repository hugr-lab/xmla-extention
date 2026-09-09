# Registers the xmla extension with DuckDB's build system.
#
# EXTENSION_VERSION is explicit. Without it DuckDB falls back to
# duckdb_extension_generate_version(), which runs `git describe` — and with no
# v*.*.* tag in this repository that does not match the semver pattern, so the
# reported version becomes a 10-character commit hash. `LOAD xmla` would then
# report something no release note mentions.
#
# LOAD_TESTS is NOT set. It registers <source>/test/sql as the sqllogictest path,
# and no such directory exists yet — test/ holds cpp, gss and hooks. The path
# being non-empty means the build's own FATAL_ERROR does not fire; the unittest
# binary is simply handed a directory that globs to nothing. It goes back when
# there is a SQL surface to test, which is T-034..T-037.
duckdb_extension_load(xmla
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    EXTENSION_VERSION "0.0.1"
)
