# Registers the xmla extension with DuckDB's build system.
#
# EXTENSION_VERSION is explicit. Without it DuckDB falls back to
# duckdb_extension_generate_version(), which runs `git describe` — and with no
# v*.*.* tag in this repository that does not match the semver pattern, so the
# reported version becomes a 10-character commit hash. `LOAD xmla` would then
# report something no release note mentions.
#
# LOAD_TESTS registers <source>/test/sql as the sqllogictest path. It is back now
# that test/sql exists and has something to say; it was removed while the
# directory was absent, where the path being non-empty meant the build's own
# FATAL_ERROR did not fire and the unittest binary was simply handed a directory
# that globbed to nothing.
duckdb_extension_load(xmla
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    EXTENSION_VERSION "0.0.1"
    LOAD_TESTS
)
