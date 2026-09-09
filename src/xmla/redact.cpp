#include "xmla/redact.hpp"

#include <cctype>
#include <regex>

namespace xmla {

namespace {

// SPNs are anchored to the service classes actually in play, NOT to a generic
// word/word shape. A generic pattern destroyed the very diagnostics this
// scrubber exists to preserve: "cannot appear under Envelope/Body" - the error
// that identified the Authenticate namespace bug - along with "text/xml", the
// content type this client negotiates, "TCP/IP" and "and/or", all became <SPN>.
//
// Case-INSENSITIVE: the conventional rendering in Kerberos/SSPI diagnostics is
// lower-case, and fault text lower-cases the class freely. The false positives
// the anchoring exists for stay excluded in every casing, and
// "http://host/soap" cannot match because the character class will not cross the
// second slash.
const std::regex &SpnPattern() {
	static const std::regex re(
		R"(\b(?:HTTP|HOST|RestrictedKrbHost|MSSQLSvc|MSOLAPSvc(?:\.[0-9]+)?|MSOLAPDisco(?:\.[0-9]+)?|ldap|cifs)/[A-Za-z0-9._-]+)",
		std::regex::icase);
	return re;
}

const std::regex &Ipv4Pattern() {
	static const std::regex re(R"(\b\d{1,3}(?:\.\d{1,3}){3}\b)");
	return re;
}

const std::regex &SidPattern() {
	static const std::regex re(R"(\bS-1-(?:\d+-)+\d+\b)");
	return re;
}

const std::regex &NetbiosPattern() {
	static const std::regex re(R"(\bWIN-[A-Z0-9]{6,}\b)");
	return re;
}

//! user@REALM, and FQDNs generally.
const std::regex &PrincipalPattern() {
	static const std::regex re(R"(\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");
	return re;
}

//! NT-style DOMAIN\user, which SSAS faults use. The lookahead-free form keeps
//! drive-letter paths out by requiring at least two characters before the
//! backslash; a Windows path being scrubbed anyway is an acceptable trade
//! against leaking an account name.
const std::regex &NtAccountPattern() {
	static const std::regex re(R"(\b[A-Za-z][A-Za-z0-9._-]+\\[A-Za-z0-9._-]+)");
	return re;
}

const std::regex &ConnectionStringPattern() {
	static const std::regex re(R"((Data Source|Provider|Initial Catalog|User ID|Password|Server)=[^;<"]*)",
							   std::regex::icase);
	return re;
}

//! Word-bounded literal replacement. An unbounded literal mangles ordinary
//! prose: a host named "h" turns "The" into "T<HOST>e", and a real host named
//! "sql" or "db" corrupts every message mentioning those letters.
std::string ReplaceLiteral(const std::string &text, const std::string &needle, const std::string &label) {
	if (needle.empty()) {
		return text;
	}
	std::string out;
	out.reserve(text.size());
	const size_t n = needle.size();
	size_t i = 0;
	auto is_word = [](char c) { return isalnum(static_cast<unsigned char>(c)) || c == '_'; };
	while (i < text.size()) {
		bool matched = false;
		if (i + n <= text.size()) {
			bool equal = true;
			for (size_t k = 0; k < n; k++) {
				if (tolower(static_cast<unsigned char>(text[i + k])) !=
					tolower(static_cast<unsigned char>(needle[k]))) {
					equal = false;
					break;
				}
			}
			if (equal) {
				const bool left_ok = (i == 0) || !is_word(text[i - 1]);
				const bool right_ok = (i + n >= text.size()) || !is_word(text[i + n]);
				if (left_ok && right_ok) {
					out += label;
					i += n;
					matched = true;
				}
			}
		}
		if (!matched) {
			out.push_back(text[i++]);
		}
	}
	return out;
}

//! Strip a scheme and any path, so "https://host/soap" contributes "host".
std::string BareHost(const std::string &in) {
	std::string s = in;
	const size_t scheme = s.find("://");
	if (scheme != std::string::npos) {
		s = s.substr(scheme + 3);
	}
	const size_t slash = s.find('/');
	if (slash != std::string::npos) {
		s = s.substr(0, slash);
	}
	return s;
}

}  // namespace

Scrubber::Scrubber(std::string host, std::string user, std::string realm)
	: host_(std::move(host)), user_(std::move(user)), realm_(std::move(realm)) {}

std::string Scrubber::operator()(const std::string &text) const {
	if (text.empty()) {
		return text;
	}
	std::string out = text;
	// Literals first: they are the tokens we actually know.
	if (!host_.empty()) {
		out = ReplaceLiteral(out, host_, "<HOST>");
		const std::string bare = BareHost(host_);
		if (bare != host_) {
			out = ReplaceLiteral(out, bare, "<HOST>");
		}
	}
	out = ReplaceLiteral(out, user_, "<USER>");
	out = ReplaceLiteral(out, realm_, "<REALM>");

	out = std::regex_replace(out, ConnectionStringPattern(), "$1=<REDACTED>");
	out = std::regex_replace(out, SidPattern(), "<SID>");
	out = std::regex_replace(out, NetbiosPattern(), "<HOST>");
	out = std::regex_replace(out, NtAccountPattern(), "<PRINCIPAL>");
	out = std::regex_replace(out, PrincipalPattern(), "<PRINCIPAL>");
	out = std::regex_replace(out, SpnPattern(), "<SPN>");
	out = std::regex_replace(out, Ipv4Pattern(), "<IP>");
	return out;
}

}  // namespace xmla
