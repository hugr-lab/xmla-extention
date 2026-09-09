#include "xmla/envelopes.hpp"

#include "xmla/errors.hpp"

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
	const char first = name[0];
	if (!(isalpha(static_cast<unsigned char>(first)) || first == '_')) {
		return false;
	}
	for (char c : name) {
		if (!(isalnum(static_cast<unsigned char>(c)) || c == '_')) {
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

std::string Execute(const std::string &statement, const std::string &catalog, const std::string &session_id) {
	return std::string("<Envelope xmlns=\"") + SOAP_NS + "\">" + SessionHeader(session_id) + "<Body><Execute xmlns=\"" +
		   XMLA_NS + "\"><Command><Statement>" + XmlEscape(statement) +
		   "</Statement></Command><Properties><PropertyList>" + Properties(catalog) +
		   "</PropertyList></Properties></Execute></Body></Envelope>";
}

}  // namespace envelopes
}  // namespace xmla
