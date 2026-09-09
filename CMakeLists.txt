cmake_minimum_required(VERSION 3.16)

# The extension name must match the entry-point function name DuckDB looks for.
set(TARGET_NAME xmla)
set(XMLA_EXTENSION_VERSION "0.0.1")

project(${TARGET_NAME} CXX)

# Do NOT set CMAKE_CXX_STANDARD here when building inside DuckDB: DuckDB's build
# system owns it, and forcing it into the cache overrides those settings and
# causes ODR issues. Only set a floor when this project is built standalone.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

include_directories(src/include)

# =============================================================================
# GSSAPI. The ONLY native dependency.
#
# Sealing is done by the negotiated security context, not by TLS, so there is no
# OpenSSL here and none may be added for that purpose (constitution:
# Security & Data-Handling Constraints).
#
# Discovery fails HARD when absent. The neighbouring mssql extension makes
# Kerberos optional because it also offers SQL authentication; here there is no
# unauthenticated path to fall back to, so a missing GSSAPI is a broken build
# rather than a reduced one.
# =============================================================================
if(APPLE)
    find_library(XMLA_GSS_FRAMEWORK GSS REQUIRED)
    set(XMLA_GSS_LIBRARIES ${XMLA_GSS_FRAMEWORK})
    set(XMLA_GSS_INCLUDE_DIRS "")
    message(STATUS "xmla: GSSAPI via ${XMLA_GSS_FRAMEWORK}")
else()
    find_package(PkgConfig REQUIRED)
    # Both are needed. libkrb5 does NOT arrive transitively through
    # krb5-gssapi.pc on at least Ubuntu 24.04: linking only -lgssapi_krb5 leaves
    # "undefined reference to krb5_free_error_message".
    pkg_check_modules(XMLA_GSSAPI REQUIRED krb5-gssapi)
    pkg_check_modules(XMLA_KRB5 REQUIRED krb5)
    set(XMLA_GSS_LIBRARIES ${XMLA_GSSAPI_LIBRARIES} ${XMLA_KRB5_LIBRARIES})
    set(XMLA_GSS_INCLUDE_DIRS ${XMLA_GSSAPI_INCLUDE_DIRS} ${XMLA_KRB5_INCLUDE_DIRS})
    link_directories(${XMLA_GSSAPI_LIBRARY_DIRS} ${XMLA_KRB5_LIBRARY_DIRS})
    message(STATUS "xmla: GSSAPI ${XMLA_GSSAPI_VERSION}, krb5 ${XMLA_KRB5_VERSION}")
endif()

# =============================================================================
# The protocol layer. No DuckDB header may be included from any of these files;
# that is what makes the suite runnable on a machine that has never contacted an
# Analysis Services instance (constitution III), and T-032 enforces it.
# =============================================================================
set(XMLA_PROTOCOL_SOURCES
    src/xmla/dime.cpp
    src/xmla/transport.cpp
)

add_library(xmla_protocol STATIC ${XMLA_PROTOCOL_SOURCES})
target_include_directories(xmla_protocol PUBLIC src/include ${XMLA_GSS_INCLUDE_DIRS})
target_link_libraries(xmla_protocol ${XMLA_GSS_LIBRARIES})
set_target_properties(xmla_protocol PROPERTIES POSITION_INDEPENDENT_CODE ON)

# =============================================================================
# Hermetic protocol tests. No sockets, no server, no DuckDB.
# =============================================================================
file(GLOB XMLA_TEST_SOURCES test/cpp/*.cpp)
add_executable(xmla_test ${XMLA_TEST_SOURCES})
target_include_directories(xmla_test PRIVATE test/cpp)
target_link_libraries(xmla_test xmla_protocol)

enable_testing()
add_test(NAME xmla_protocol_tests COMMAND xmla_test)
