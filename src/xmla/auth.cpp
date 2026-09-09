#include "xmla/auth.hpp"

#include "xmla/errors.hpp"
#include "xmla/rowset.hpp"

namespace xmla {
namespace auth {

namespace {
const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int DecodeChar(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	return -1;
}
}  // namespace

std::string Base64Encode(const Bytes &in) {
	std::string out;
	out.reserve(((in.size() + 2) / 3) * 4);
	size_t i = 0;
	while (i + 2 < in.size()) {
		const uint32_t n = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8) | in[i + 2];
		out.push_back(kAlphabet[(n >> 18) & 63]);
		out.push_back(kAlphabet[(n >> 12) & 63]);
		out.push_back(kAlphabet[(n >> 6) & 63]);
		out.push_back(kAlphabet[n & 63]);
		i += 3;
	}
	if (i + 1 == in.size()) {
		const uint32_t n = static_cast<uint32_t>(in[i]) << 16;
		out.push_back(kAlphabet[(n >> 18) & 63]);
		out.push_back(kAlphabet[(n >> 12) & 63]);
		out += "==";
	} else if (i + 2 == in.size()) {
		const uint32_t n = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
		out.push_back(kAlphabet[(n >> 18) & 63]);
		out.push_back(kAlphabet[(n >> 12) & 63]);
		out.push_back(kAlphabet[(n >> 6) & 63]);
		out.push_back('=');
	}
	return out;
}

bool Base64Decode(const std::string &in, Bytes &out) {
	out.clear();
	uint32_t buffer = 0;
	int bits = 0;
	size_t padding = 0;
	for (char c : in) {
		if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
			continue;
		}
		if (c == '=') {
			padding++;
			continue;
		}
		// Padding must be terminal: data after it means the input is not one
		// encoding but two concatenated, which would decode to something the
		// sender never wrote.
		if (padding != 0) {
			return false;
		}
		const int v = DecodeChar(c);
		if (v < 0) {
			return false;
		}
		buffer = (buffer << 6) | static_cast<uint32_t>(v);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
		}
	}
	if (padding > 2) {
		return false;
	}
	// Leftover bits must be zero; anything else is a truncated encoding.
	return bits < 6 && ((buffer & ((1u << bits) - 1)) == 0);
}

std::string ExtractToken(const std::string &response_xml) {
	std::string token;
	if (FindElementText(response_xml, "SspiHandshake", token)) {
		return token;
	}
	if (FindElementText(response_xml, "return", token)) {
		return token;
	}
	throw ProtocolError("AuthenticateResponse carried no security token");
}

void Handshake(GssContext &context, const SendAuthenticate &send, int max_rounds) {
	Bytes in_token;
	for (int round = 0; round < max_rounds; round++) {
		const Bytes out_token = context.Step(in_token);
		in_token.clear();

		if (context.IsComplete() && out_token.empty()) {
			return;
		}
		if (out_token.empty()) {
			throw AuthenticationError("the security context produced no token and did not complete");
		}

		const std::string response = send(Base64Encode(out_token));

		// The caller fault-checks the response, INCLUDING this terminal one. For
		// NTLM the client context completes the moment it emits its last token,
		// so a handshake that returned here without the caller having inspected
		// the reply would drop a "Logon failure" and report success.
		if (context.IsComplete()) {
			return;
		}

		const std::string encoded = ExtractToken(response);
		if (encoded.empty()) {
			continue;
		}
		if (!Base64Decode(encoded, in_token)) {
			throw ProtocolError("the server's security token was not valid base64");
		}
	}
	throw AuthenticationError("the handshake did not complete within " + std::to_string(max_rounds) + " rounds");
}

}  // namespace auth
}  // namespace xmla
