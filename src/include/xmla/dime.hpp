//===----------------------------------------------------------------------===//
// DIME record framing for the Analysis Services TCP binding.
//
// [MS-SSAS] "TCP":
//   "When using TCP as the transport, the client and server MUST compose
//    messages by using Direct Internet Message Encapsulation [DIME]."
//   https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/
//       f172a52f-f69e-4051-8b3a-627433e978fb
//
// Record header, 12 bytes:
//
//   byte 0     VERSION (5 bits, MUST be 1) | MB (1) | ME (1) | CF (1)
//   byte 1     TYPE_T (4 bits) | RESERVED (4 bits, MUST be 0)
//   bytes 2-3  OPTIONS_LENGTH (16)
//   bytes 4-5  ID_LENGTH      (16)
//   bytes 6-7  TYPE_LENGTH    (16)
//   bytes 8-11 DATA_LENGTH    (32)
//
// then OPTIONS, ID, TYPE and DATA in that order, EACH PADDED SEPARATELY to a
// 4-byte boundary. The declared lengths exclude their own padding, which is the
// detail that makes a naive reader desync.
//
// Content type is negotiated through the first OPTIONS byte. Binary XML
// [MS-BINXML] and XPRESS compression are OPTIONAL and negotiated, so this
// implementation requests neither and implements neither (research D2). That
// single decision is what keeps the extension small.
//===----------------------------------------------------------------------===//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace xmla {
namespace dime {

using Bytes = std::vector<uint8_t>;

static const uint8_t VERSION = 1;
static const size_t HEADER_LEN = 12;

//! TYPE values from the [MS-SSAS] TCP content-type table.
extern const char *const TYPE_TEXT_XML;
extern const char *const TYPE_BINARY_XML;
extern const char *const TYPE_COMPRESSED_XML;
extern const char *const TYPE_COMPRESSED_BINARY_XML;

// OPTIONS: 4 bytes, only the first is used; the remaining three are reserved and
// MUST be zero. Bits run from least significant upward.
enum Options : uint8_t {
	OPT_NEGO = 0x01,
	OPT_REQ_SX = 0x02,
	OPT_REQ_XPRESS = 0x04,
	OPT_RESP_SX = 0x08,
	OPT_RESP_XPRESS = 0x10
};

//! What this client asks for: nothing binary, nothing compressed.
//
// RESP_XPRESS matters more than it looks. Setting it makes the server return
// XPRESS-compressed XML, which arrives as convincing-looking garbage rather than
// an error. The reference Microsoft client sets it; we must not, having no
// decompressor.
Bytes OptionsClearText();
//! NEGO is clear on the first record and set on every later one.
Bytes OptionsNegotiated();

struct Record {
	Bytes data;
	std::string type_ = TYPE_TEXT_XML;
	Bytes options = OptionsClearText();
	Bytes id;
	bool mb = true;
	bool me = true;
	bool cf = false;
	uint8_t type_t = 1;

	Bytes Encode() const;
};

//! Decode one record starting at `offset`. Returns the record; sets
//! `next_offset` to where the following record begins.
//!
//! Throws IncompleteMessage when more bytes are needed - INCLUDING when the
//! declared bytes have arrived but their padding has not. Reporting such a
//! record as decoded leaves the pad bytes in the stream, where they are read as
//! the next message's header and surface as a bogus "unsupported DIME version" -
//! a desync disguised as a protocol error, one message from its cause.
Record DecodeRecord(const uint8_t *buf, size_t len, size_t offset, size_t &next_offset);

//! Encode a whole message as a single DIME record (MB and ME both set).
Bytes EncodeMessage(const Bytes &payload, const std::string &type_ = TYPE_TEXT_XML);

struct DecodedMessage {
	Bytes payload;
	std::string content_type;
	Bytes options;
	size_t next_offset = 0;
};

//! Reassemble one DIME message starting at `offset`.
//!
//! `next_offset` matters: a peer may pack several messages into one TCP segment,
//! so the caller must keep the remainder rather than discarding the read buffer.
//!
//! Per [MS-SSAS] a chunked sequence "is required to be encapsulated entirely
//! within one DIME message and cannot span across multiple DIME messages", so
//! reassembly stops at the record whose ME bit is set.
DecodedMessage DecodeMessageAt(const uint8_t *buf, size_t len, size_t offset);

//! Fail loudly if the server selected an encoding we deliberately do not
//! implement. A refusal is a scope change to report, not a fallback to absorb.
void CheckNegotiated(const Bytes &record_options, const std::string &record_type);

}  // namespace dime
}  // namespace xmla
