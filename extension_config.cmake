# Registers the xmla extension with DuckDB's build system.
duckdb_extension_load(xmla
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)
