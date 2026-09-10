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
# GSSAPI. The ONLY native dependency, and it is needed by exactly one file.
#
# Sealing is done by the negotiated security context, not by TLS, so there is no
# OpenSSL here and none may be added for that purpose (constitution:
# Security & Data-Handling Constraints).
#
# macOS is not simply "GSS.framework". Apple's framework DECLARES the IOV types
# and constants but exports neither gss_wrap_iov nor gss_unwrap_iov, and ships no
# NTLM mechanism -- verified by inspecting the SDK headers and `nm -gU` on the
# framework binary (research D11). A build against it therefore cannot seal a
# Kerberos message and cannot speak NTLM at all, so MIT krb5 (Homebrew `krb5`) is
# preferred there and the framework is only a fallback that says what it cannot
# do.
# =============================================================================
find_package(PkgConfig QUIET)

set(XMLA_GSS_FOUND FALSE)

if(PkgConfig_FOUND)
    # Both are needed. libkrb5 does NOT arrive transitively through
    # krb5-gssapi.pc on at least Ubuntu 24.04: linking only -lgssapi_krb5 leaves
    # "undefined reference to krb5_free_error_message".
    pkg_check_modules(XMLA_GSSAPI QUIET krb5-gssapi)
    pkg_check_modules(XMLA_KRB5 QUIET krb5)
    if(XMLA_GSSAPI_FOUND AND XMLA_KRB5_FOUND)
        set(XMLA_GSS_FOUND TRUE)
        set(XMLA_GSS_INCLUDE_DIRS ${XMLA_GSSAPI_INCLUDE_DIRS} ${XMLA_KRB5_INCLUDE_DIRS})

        # ABSOLUTE paths, not `-lname` plus link_directories().
        #
        # link_directories() applies to targets created in the SAME directory
        # scope and below, and the extension's archive is linked into DuckDB's
        # own targets, which are created in duckdb/'s scope. The -L therefore
        # never reached the link line: verified on the failing command, which
        # carried `-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err` and no -L at all.
        #
        # On macOS that is not a missing library, it is the WRONG one. Apple
        # ships /usr/lib/libgssapi_krb5.dylib as a Heimdal-backed shim, so the
        # link succeeds at finding it and then fails on exactly the symbols the
        # keg-only Homebrew krb5 was installed to provide -- gss_wrap_iov,
        # gss_unwrap_iov, gss_wrap_iov_length, gss_release_iov_buffer and
        # gss_acquire_cred_with_password. The documented instruction in the
        # error message below (brew install krb5, then PKG_CONFIG_PATH=...) did
        # not work as written until this resolved each name to a full path.
        #
        # Where pkg-config reports no library directory -- the ordinary Linux
        # case, where the libraries are on the default search path -- the plain
        # name is kept and the linker resolves it as before.
        set(XMLA_GSS_LIBRARIES "")
        foreach(xmla_gss_lib IN LISTS XMLA_GSSAPI_LIBRARIES XMLA_KRB5_LIBRARIES)
            find_library(XMLA_GSS_LIB_${xmla_gss_lib}
                NAMES ${xmla_gss_lib}
                HINTS ${XMLA_GSSAPI_LIBRARY_DIRS} ${XMLA_KRB5_LIBRARY_DIRS}
                NO_DEFAULT_PATH)
            if(XMLA_GSS_LIB_${xmla_gss_lib})
                list(APPEND XMLA_GSS_LIBRARIES ${XMLA_GSS_LIB_${xmla_gss_lib}})
            else()
                list(APPEND XMLA_GSS_LIBRARIES ${xmla_gss_lib})
            endif()
        endforeach()
        message(STATUS "xmla: MIT GSSAPI ${XMLA_GSSAPI_VERSION}, krb5 ${XMLA_KRB5_VERSION}")
    endif()
endif()

# Apple's GSS.framework is detected only so the failure below can say something
# useful. It is NOT accepted as a GSSAPI: it declares the IOV types and constants
# but exports neither gss_wrap_iov nor gss_unwrap_iov, and ships no NTLM
# mechanism (research D11, verified with `nm -gU` on the framework binary). A
# build against it would configure, compile most of the way, and then be unable
# to seal a single message -- a runtime failure standing in for a build-time one.
set(XMLA_APPLE_FRAMEWORK_ONLY FALSE)
if(NOT XMLA_GSS_FOUND AND APPLE)
    find_library(XMLA_GSS_FRAMEWORK GSS)
    if(XMLA_GSS_FRAMEWORK)
        set(XMLA_APPLE_FRAMEWORK_ONLY TRUE)
    endif()
endif()

# The extension cannot authenticate without GSSAPI and there is no
# unauthenticated path to fall back to, so a missing GSSAPI is a broken build --
# NOT a reduced one, which is the choice the neighbouring mssql extension makes
# because it also offers SQL authentication.
#
# The hermetic protocol tests are the exception and are built regardless: they
# must pass on a machine that has never contacted an Analysis Services instance
# (constitution III), and that machine may equally never have had a Kerberos
# library on it.
option(XMLA_REQUIRE_GSS "Fail the build when GSSAPI is missing" ON)
if(NOT XMLA_GSS_FOUND AND XMLA_REQUIRE_GSS)
    if(XMLA_APPLE_FRAMEWORK_ONLY)
        message(FATAL_ERROR
            "xmla: Apple's GSS.framework was found but cannot be used. It exports no "
            "gss_wrap_iov and ships no NTLM mechanism, so no message could be sealed. "
            "Install MIT krb5 and point pkg-config at it:\n"
            "    brew install krb5\n"
            "    PKG_CONFIG_PATH=$(brew --prefix krb5)/lib/pkgconfig cmake -S . -B build\n"
            "Or configure with -DXMLA_REQUIRE_GSS=OFF to build only the hermetic "
            "protocol tests, which need no security library.")
    endif()
    message(FATAL_ERROR
        "xmla: no GSSAPI. Install libkrb5-dev (Debian/Ubuntu), krb5-devel (RHEL/Fedora) "
        "or krb5 (Homebrew). Configure with -DXMLA_REQUIRE_GSS=OFF to build only the "
        "hermetic protocol tests, which need no security library.")
endif()

# =============================================================================
# The protocol layer. No DuckDB header may be included from any of these files;
# that is what makes the suite runnable on a machine that has never contacted an
# Analysis Services instance (constitution III), and T-032 enforces it.
# =============================================================================
set(XMLA_PROTOCOL_SOURCES
    src/xmla/connection_string.cpp
    src/xmla/dime.cpp
    src/xmla/transport.cpp
    src/xmla/sealing.cpp
    src/xmla/rowset.cpp
    src/xmla/envelopes.cpp
    src/xmla/redact.cpp
    src/xmla/auth.cpp
    src/xmla/client.cpp
)

add_library(xmla_protocol STATIC ${XMLA_PROTOCOL_SOURCES})
target_include_directories(xmla_protocol PUBLIC src/include)
set_target_properties(xmla_protocol PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The GSS binding is its own target so that xmla_protocol links no security
# library at all. That is not tidiness: it is what lets the hermetic suite build
# and run where no GSSAPI exists, and it makes "did a protocol source acquire a
# GSS dependency?" a link error rather than a review question.
if(XMLA_GSS_FOUND)
    add_library(xmla_gss STATIC src/xmla/gss_context.cpp)
    target_include_directories(xmla_gss PUBLIC src/include PRIVATE ${XMLA_GSS_INCLUDE_DIRS})
    target_link_libraries(xmla_gss xmla_protocol ${XMLA_GSS_LIBRARIES})
    set_target_properties(xmla_gss PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# =============================================================================
# Hermetic protocol tests. No sockets, no server, no DuckDB.
# =============================================================================
file(GLOB XMLA_TEST_SOURCES test/cpp/*.cpp)
# Whether the tests are part of the DEFAULT target is an option, defaulting ON.
#
# CodeQL needs them OUT, so it can say `cmake --build build` and analyse exactly
# the shipped code without a hardcoded target list that would silently drop a new
# target. But making EXCLUDE_FROM_ALL unconditional broke two documented entry
# points and said nothing: README's `cmake --build build && ./build/xmla_test`
# produced no binary, and `ctest` reported a missing executable because CTest
# does not build a test's dependencies.
#
# So the exclusion is now requested where it is wanted (-DXMLA_BUILD_TESTS=OFF in
# codeql.yml) rather than imposed on everyone.
option(XMLA_BUILD_TESTS "Build the hermetic protocol tests as part of the default target" ON)
if(XMLA_BUILD_TESTS)
    add_executable(xmla_test ${XMLA_TEST_SOURCES})
else()
    add_executable(xmla_test EXCLUDE_FROM_ALL ${XMLA_TEST_SOURCES})
endif()
target_include_directories(xmla_test PRIVATE test/cpp)
target_link_libraries(xmla_test xmla_protocol)

# =============================================================================
# The spike. Proves the risky path end to end against a live instance before any
# DuckDB integration exists. Needs GSSAPI; skipped when it is absent.
# =============================================================================
if(XMLA_GSS_FOUND)
    add_executable(xmla_probe tools/xmla_probe.cpp)
    target_link_libraries(xmla_probe xmla_gss xmla_protocol)
endif()

enable_testing()
add_test(NAME xmla_protocol_tests COMMAND xmla_test)

# =============================================================================
# The DuckDB extension itself.
#
# Only when DuckDB's build system is driving this file: `build_loadable_extension`
# is defined by DuckDB's CMake, so a standalone configure (which is how the
# hermetic protocol suite is built, and how a contributor with no DuckDB checkout
# builds) skips this block entirely rather than failing on an unknown command.
# =============================================================================
if(COMMAND build_loadable_extension)
    set(EXTENSION_NAME ${TARGET_NAME}_extension)
    set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

    # The protocol sources are compiled INTO the extension rather than linked as
    # a static library. build_static_extension puts its target in DuckDB's export
    # set, and CMake then requires every linked target to be exported too --
    # which would drag xmla_protocol and xmla_gss into DuckDB's install interface
    # for no benefit. Compiling them in costs one extra compile of ~10 files.
    #
    # The layering rule is unaffected: it is enforced at SOURCE level by
    # scripts/ci/check_layering.sh, not by which library a file lands in.
    set(XMLA_EXTENSION_SOURCES
        src/xmla_extension.cpp
        src/xmla_connection.cpp
        src/xmla_secret.cpp
        src/xmla_functions.cpp
        src/xmla_storage.cpp
        src/catalog/xmla_catalog.cpp
        src/catalog/xmla_schema_entry.cpp
        src/catalog/xmla_table_entry.cpp
        src/catalog/xmla_transaction.cpp
        ${XMLA_PROTOCOL_SOURCES})
    if(XMLA_GSS_FOUND)
        list(APPEND XMLA_EXTENSION_SOURCES src/xmla/gss_context.cpp)
    endif()

    build_static_extension(${TARGET_NAME} ${XMLA_EXTENSION_SOURCES})
    build_loadable_extension(${TARGET_NAME} " " ${XMLA_EXTENSION_SOURCES})

    foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
        target_include_directories(${target} PRIVATE src/include ${XMLA_GSS_INCLUDE_DIRS})
        if(XMLA_GSS_FOUND)
            target_link_libraries(${target} ${XMLA_GSS_LIBRARIES})
        endif()
        target_compile_definitions(${target} PRIVATE XMLA_VERSION="${XMLA_EXTENSION_VERSION}")
    endforeach()

    install(
        TARGETS ${EXTENSION_NAME}
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

    message(STATUS "xmla: extension targets configured (DuckDB build)")
else()
    message(STATUS "xmla: standalone build - protocol library and tests only")
endif()
