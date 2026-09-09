//===----------------------------------------------------------------------===//
// Remove identifying tokens from anything that could reach a log or an error.
//
// Constitution I binds harder here than in a text protocol: this code handles
// GSS/SPNEGO tokens, which carry the principal, the realm and the target
// service. Nothing built from those may be logged, and no message body reaches a
// caller un-scrubbed.
//===----------------------------------------------------------------------===//
#pragma once

#include <string>

namespace xmla {

class Scrubber {
public:
	//! Literal host/user/realm are removed first because they are the tokens we
	//! know; the patterns then catch the shapes we do not know in advance.
	Scrubber(std::string host = std::string(), std::string user = std::string(), std::string realm = std::string());

	std::string operator()(const std::string &text) const;

private:
	std::string host_;
	std::string user_;
	std::string realm_;
};

}  // namespace xmla
