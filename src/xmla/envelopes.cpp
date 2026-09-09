#include "xmla/envelopes.hpp"

#include "xmla/errors.hpp"

#include <algorithm>
#include <cctype>

namespace xmla {
namespace envelopes {

const char *const SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
const char *const XMLA_NS = "urn:schemas-microsoft-com:xml-analysis";
const char *const EXT_NS = "http://schemas.microsoft.com/analysisservices/2003/ext";

std::string XmlEscape(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	for (char c : in) {
		switch (c) {
		case '&':
			out += "&amp;";
			break;
		case '<':
			out += "&lt;";
			break;
		case '>':
			out += "&gt;";
			break;
		case '"':
			out += "&quot;";
			break;
		case '\'':
			out += "&apos;";
			break;
		default:
			out.push_back(c);
		}
	}
	return out;
}

namespace {

// CANARY: a deliberately unreachable static, to prove CodeQL still analyses
// src/ after test/cpp was excluded. Reverted immediately.
static int CodeqlCanaryUnusedFunction(int x) {
	return x * 2;
}

//! ASCII-only case fold and classification.
//!
//! ::toupper and isalpha follow the global LC_CTYPE, and a DuckDB extension is
//! loaded into a host process that may well have called setlocale(LC_CTYPE, "")
//! -- CPython does, and so does R. Under tr_TR.UTF-8, toupper('i') is not 'I',
//! so a lower-case "with member ... select ..." folds to "WiTH" and a
//! legitimate query is refused. Keyword syntax here is ASCII by definition, so
//! the locale has no business in it.
static char AsciiUpper(char c) {
	return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

static bool AsciiAlpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static bool AsciiSpace(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

//! Restriction names are XMLA rowset column names: letter or underscore, then
//! letters, digits and underscores.
//!
//! VALIDATED rather than escaped, because an element NAME cannot be made safe by
//! escaping - it has to be rejected. This is the one parameter on the public
//! surface through which caller text reaches the wire as markup rather than as
//! content, so a crafted value could otherwise close RestrictionList and inject
//! sibling elements.
bool IsValidRestrictionName(const std::string &name) {
	if (name.empty() || name.size() > 128) {
		return false;
	}
	// ASCII-only, for the same reason as the keyword fold below: an XMLA rowset
	// column name is ASCII by definition, and isalpha/isalnum follow LC_CTYPE.
	const char first = name[0];
	if (!(AsciiAlpha(first) || first == '_')) {
		return false;
	}
	for (char c : name) {
		if (!(AsciiAlpha(c) || (c >= '0' && c <= '9') || c == '_')) {
			return false;
		}
	}
	return true;
}

std::string Properties(const std::string &catalog) {
	if (catalog.empty()) {
		return std::string();
	}
	return "<Catalog>" + XmlEscape(catalog) + "</Catalog>";
}

std::string RestrictionList(const Restrictions &restrictions) {
	std::string out;
	for (const auto &entry : restrictions) {
		if (!IsValidRestrictionName(entry.first)) {
			// The name is not echoed back: it is caller-supplied text and this
			// message can reach a log.
			throw ProtocolError("invalid restriction name; expected an XMLA rowset column name");
		}
		out += "<" + entry.first + ">" + XmlEscape(entry.second) + "</" + entry.first + ">";
	}
	return out;
}

}  // namespace

std::string Authenticate(const std::string &token_b64) {
	return std::string("<Envelope xmlns=\"") + SOAP_NS + "\"><Body><Authenticate xmlns=\"" + EXT_NS +
		   "\"><SspiHandshake>" + token_b64 + "</SspiHandshake></Authenticate></Body></Envelope>";
}

std::string SessionHeader(const std::string &session_id) {
	if (session_id.empty()) {
		return std::string("<Header><BeginSession xmlns=\"") + XMLA_NS + "\" mustUnderstand=\"1\"/></Header>";
	}
	return std::string("<Header><Session xmlns=\"") + XMLA_NS + "\" mustUnderstand=\"1\" SessionId=\"" +
		   XmlEscape(session_id) + "\"/></Header>";
}

std::string Discover(const std::string &request_type, const Restrictions &restrictions, const std::string &catalog,
					 const std::string &session_id) {
	return std::string("<Envelope xmlns=\"") + SOAP_NS + "\">" + SessionHeader(session_id) +
		   "<Body><Discover xmlns=\"" + XMLA_NS + "\"><RequestType>" + XmlEscape(request_type) +
		   "</RequestType><Restrictions><RestrictionList>" + RestrictionList(restrictions) +
		   "</RestrictionList></Restrictions><Properties><PropertyList>" + Properties(catalog) +
		   "</PropertyList></Properties></Discover></Body></Envelope>";
}

//! Advance past whitespace and comments starting at `i`. Returns false if the
//! input ends inside an unterminated comment.
static bool SkipTrivia(const std::string &s, size_t &i) {
	for (;;) {
		while (i < s.size() && AsciiSpace(s[i])) {
			i++;
		}
		if (s.compare(i, 2, "//") == 0 || s.compare(i, 2, "--") == 0) {
			const size_t nl = s.find('\n', i);
			if (nl == std::string::npos) {
				i = s.size();
				return true;
			}
			i = nl + 1;
			continue;
		}
		if (s.compare(i, 2, "/*") == 0) {
			const size_t close = s.find("*/", i + 2);
			if (close == std::string::npos) {
				i = s.size();
				return false;
			}
			i = close + 2;
			continue;
		}
		return true;
	}
}

//! Refuse a statement separator outside a string or a bracketed identifier.
//!
//! Checking only the FIRST keyword is the classic allowlist bypass: SSMS sends
//! semicolon-separated MDX as a single XMLA Execute/Statement, so
//! "SELECT {} ON 0 FROM [S]; UPDATE CUBE [S] SET (x) = 0" would satisfy a
//! first-token check and carry a writeback behind it.
//!
//! Whether SSAS executes every statement in such a batch is NOT verified here
//! and this does not assume an answer. It refuses the shape, which is the
//! conservative reading and the one consistent with this guard's posture. A
//! TRAILING separator is allowed because it is idiomatic and carries nothing.
static void RejectStatementBatch(const std::string &s) {
	size_t i = 0;
	while (i < s.size()) {
		const char c = s[i];
		if (c == '\'' || c == '"') {
			// A quoted literal. Doubling the quote escapes it in both MDX and DAX.
			const char quote = c;
			i++;
			while (i < s.size()) {
				if (s[i] == quote) {
					if (i + 1 < s.size() && s[i + 1] == quote) {
						i += 2;
						continue;
					}
					i++;
					break;
				}
				i++;
			}
			continue;
		}
		if (c == '[') {
			// A bracketed identifier; "]]" escapes a literal bracket.
			i++;
			while (i < s.size()) {
				if (s[i] == ']') {
					if (i + 1 < s.size() && s[i + 1] == ']') {
						i += 2;
						continue;
					}
					i++;
					break;
				}
				i++;
			}
			continue;
		}
		if (s.compare(i, 2, "//") == 0 || s.compare(i, 2, "--") == 0 || s.compare(i, 2, "/*") == 0) {
			size_t j = i;
			SkipTrivia(s, j);
			// SkipTrivia also eats whitespace, which is harmless here.
			if (j <= i) {
				i++;
			} else {
				i = j;
			}
			continue;
		}
		if (c == ';') {
			size_t j = i + 1;
			SkipTrivia(s, j);
			if (j >= s.size()) {
				return;	 // trailing separator, nothing behind it
			}
			throw ProtocolError(
				"this extension sends a single read-only statement, and this one "
				"contains a statement separator with further text after it");
		}
		i++;
	}
}

void RejectIfMutating(const std::string &statement) {
	// Skip whitespace and comments to find the first significant token. Comments
	// are skipped rather than rejected because a query may legitimately begin
	// with one; skipping them is what stops "/*x*/ UPDATE CUBE" from reading as
	// an unrecognised keyword and being refused for the wrong reason -- and, more
	// to the point, from being ACCEPTED if the allowlist were applied to the raw
	// first characters.
	size_t i = 0;
	SkipTrivia(statement, i);

	size_t end = i;
	while (end < statement.size() && (AsciiAlpha(statement[end]) || statement[end] == '_')) {
		end++;
	}
	std::string keyword = statement.substr(i, end - i);
	std::transform(keyword.begin(), keyword.end(), keyword.begin(), AsciiUpper);

	// The complete set of statement forms this extension will send. MDX queries
	// start SELECT or WITH; DAX queries start EVALUATE, DEFINE or VAR.
	static const char *const kQueryKeywords[] = {"SELECT", "EVALUATE", "WITH", "DEFINE", "VAR"};
	bool allowed_keyword = false;
	for (const char *allowed : kQueryKeywords) {
		if (keyword == allowed) {
			allowed_keyword = true;
			break;
		}
	}
	if (allowed_keyword) {
		// The first token being a query keyword says nothing about the rest.
		RejectStatementBatch(statement);
		return;
	}

	// The statement is NOT echoed back. It is caller text and this message can
	// reach a log; the keyword alone is enough to act on.
	throw ProtocolError(
		"this extension sends only read-only statements, and the statement does not "
		"begin with SELECT, EVALUATE, WITH, DEFINE or VAR" +
		(keyword.empty() ? std::string() : std::string(" (it begins with ") + keyword + ")"));
}

std::string Execute(const std::string &statement, const std::string &catalog, const std::string &session_id) {
	RejectIfMutating(statement);
	return std::string("<Envelope xmlns=\"") + SOAP_NS + "\">" + SessionHeader(session_id) + "<Body><Execute xmlns=\"" +
		   XMLA_NS + "\"><Command><Statement>" + XmlEscape(statement) +
		   "</Statement></Command><Properties><PropertyList>" + Properties(catalog) +
		   "</PropertyList></Properties></Execute></Body></Envelope>";
}

}  // namespace envelopes
}  // namespace xmla
