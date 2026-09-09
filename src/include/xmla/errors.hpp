//===----------------------------------------------------------------------===//
// The failure categories a caller can act on.
//
// Distinct types rather than one error carrying a code, because they demand
// different operator actions: a connection failure means check the network, an
// authentication failure means check the ticket, an authorization failure means
// check permissions. Collapsing them forces callers to parse message text.
//===----------------------------------------------------------------------===//
#pragma once

#include <stdexcept>
#include <string>

namespace xmla {

class XmlaError : public std::runtime_error {
public:
	explicit XmlaError(const std::string &message, const std::string &detail = std::string())
		: std::runtime_error(detail.empty() ? message : message + ": " + detail), message_(message), detail_(detail) {}

	//! The category's own message, without the server's explanation appended.
	const std::string &message() const {
		return message_;
	}
	//! The server's own explanation where one exists. Scrubbed before it gets here.
	const std::string &detail() const {
		return detail_;
	}

private:
	std::string message_;
	std::string detail_;
};

//! Never reached a server. Check host, port, firewall.
class ConnectionError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! Reached the server; identity could not be established. Check ticket/keytab.
class AuthenticationError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! Identity established; access refused. Check the account's permissions.
class AuthorizationError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! The server understood the request and rejected it. Read detail().
class ServerError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! The server declined the message encoding we asked for.
//
// Its own category because it is not an ordinary failure: this extension
// negotiates clear-text XML precisely so it can skip binary XML and compression
// entirely. A refusal means that assumption is wrong and the project's scope
// changes, so it must surface loudly rather than being retried around.
class NegotiationError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! The bytes on the wire did not match what the specification requires.
class ProtocolError : public XmlaError {
public:
	using XmlaError::XmlaError;
};

//! Not enough bytes yet - read more and retry.
//
// A distinct TYPE rather than a flag on ProtocolError because the reader has to
// tell "keep reading" from "this is malformed", and doing that by matching on
// message text is fragile: a chunked message split at a record boundary is
// incomplete but says nothing about truncation, so it was treated as fatal.
// Deriving from ProtocolError keeps a single catch site correct for callers who
// genuinely want both.
class IncompleteMessage : public ProtocolError {
public:
	using ProtocolError::ProtocolError;
};

}  // namespace xmla
