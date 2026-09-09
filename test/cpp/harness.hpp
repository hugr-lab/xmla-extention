//===----------------------------------------------------------------------===//
// A ~90-line test harness, deliberately.
//
// The protocol layer must be testable BEFORE the DuckDB submodule exists
// (constitution III, and the spike ordering in tasks.md), so the first tests
// cannot use DuckDB's vendored Catch2. The macro names match Catch2's so the
// migration in T-003 is mechanical rather than a rewrite.
//===----------------------------------------------------------------------===//
#pragma once

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace harness {

struct Case {
	std::string name;
	std::function<void()> fn;
};

inline std::vector<Case> &Registry() {
	static std::vector<Case> cases;
	return cases;
}

struct Registrar {
	Registrar(const std::string &name, std::function<void()> fn) {
		Registry().push_back(Case{name, fn});
	}
};

struct Failure : std::exception {
	std::string what_;
	explicit Failure(std::string w) : what_(std::move(w)) {}
	const char *what() const noexcept override {
		return what_.c_str();
	}
};

inline int RunAll() {
	int failed = 0;
	for (const auto &c : Registry()) {
		try {
			c.fn();
			std::printf("  ok    %s\n", c.name.c_str());
		} catch (const std::exception &e) {
			std::printf("  FAIL  %s\n        %s\n", c.name.c_str(), e.what());
			failed++;
		}
	}
	std::printf("\n%d case(s), %d failed\n", static_cast<int>(Registry().size()), failed);
	return failed == 0 ? 0 : 1;
}

}  // namespace harness

#define XMLA_CAT2(a, b) a##b
#define XMLA_CAT(a, b) XMLA_CAT2(a, b)

#define TEST_CASE(name)                                                                            \
	static void XMLA_CAT(xmla_test_, __LINE__)();                                                  \
	static harness::Registrar XMLA_CAT(xmla_reg_, __LINE__)(name, XMLA_CAT(xmla_test_, __LINE__)); \
	static void XMLA_CAT(xmla_test_, __LINE__)()

#define REQUIRE(expr)                                                                          \
	do {                                                                                       \
		if (!(expr)) {                                                                         \
			throw harness::Failure(std::string("REQUIRE failed: " #expr " at " __FILE__ ":") + \
								   std::to_string(__LINE__));                                  \
		}                                                                                      \
	} while (0)

#define REQUIRE_EQ(a, b)                                                                                 \
	do {                                                                                                 \
		auto _a = (a);                                                                                   \
		auto _b = (b);                                                                                   \
		if (!(_a == _b)) {                                                                               \
			throw harness::Failure(std::string("REQUIRE_EQ failed: " #a " == " #b " at " __FILE__ ":") + \
								   std::to_string(__LINE__));                                            \
		}                                                                                                \
	} while (0)

//! Asserts the EXACT type, not a base. Distinguishing IncompleteMessage from
//! ProtocolError is the whole point of having two types (FR-003), and a matcher
//! that accepts a base class would pass on the bug it exists to catch.
#define REQUIRE_THROWS_EXACTLY(Type, expr)                                                                 \
	do {                                                                                                   \
		bool _caught = false;                                                                              \
		try {                                                                                              \
			(void)(expr);                                                                                  \
		} catch (const Type &) {                                                                           \
			_caught = true;                                                                                \
		} catch (const std::exception &_e) {                                                               \
			throw harness::Failure(std::string("expected " #Type ", got a different type: ") + _e.what() + \
								   " at " __FILE__ ":" + std::to_string(__LINE__));                        \
		}                                                                                                  \
		if (!_caught) {                                                                                    \
			throw harness::Failure(std::string("expected " #Type ", nothing thrown, at " __FILE__ ":") +   \
								   std::to_string(__LINE__));                                              \
		}                                                                                                  \
	} while (0)
