#include "xmla/dime.hpp"

#include "xmla/errors.hpp"

namespace xmla {
namespace dime {

const char *const TYPE_TEXT_XML = "text/xml";
const char *const TYPE_BINARY_XML = "application/sx";
const char *const TYPE_COMPRESSED_XML = "application/xml+xpress";
const char *const TYPE_COMPRESSED_BINARY_XML = "application/sx+xpress";

Bytes OptionsClearText() {
	return Bytes(4, 0);
}

Bytes OptionsNegotiated() {
	Bytes o(4, 0);
	o[0] = OPT_NEGO;
	return o;
}

//! Bytes of padding needed to reach the next 4-byte boundary.
static size_t Pad(size_t n) {
	return (4 - (n % 4)) % 4;
}

static void AppendField(Bytes &out, const uint8_t *field, size_t len) {
	out.insert(out.end(), field, field + len);
	out.insert(out.end(), Pad(len), 0);
}

Bytes Record::Encode() const {
	if (options.size() % 4 != 0) {
		throw ProtocolError("OPTIONS must be a whole number of 4-byte words");
	}
	if (options.size() > 0xFFFF || id.size() > 0xFFFF || type_.size() > 0xFFFF) {
		throw ProtocolError("a DIME record field exceeds its uint16 length");
	}
	if (data.size() > 0xFFFFFFFFull) {
		throw ProtocolError("DIME DATA exceeds its uint32 length");
	}
	const uint8_t flags =
		static_cast<uint8_t>((VERSION << 3) | ((mb ? 1 : 0) << 2) | ((me ? 1 : 0) << 1) | (cf ? 1 : 0));

	Bytes out;
	out.reserve(HEADER_LEN + options.size() + id.size() + type_.size() + data.size() + 12);
	out.push_back(flags);
	out.push_back(static_cast<uint8_t>((type_t & 0x0F) << 4));
	// All DIME header integers are big-endian.
	const uint16_t opt_len = static_cast<uint16_t>(options.size());
	const uint16_t id_len = static_cast<uint16_t>(id.size());
	const uint16_t type_len = static_cast<uint16_t>(type_.size());
	const uint32_t data_len = static_cast<uint32_t>(data.size());
	out.push_back(static_cast<uint8_t>(opt_len >> 8));
	out.push_back(static_cast<uint8_t>(opt_len & 0xFF));
	out.push_back(static_cast<uint8_t>(id_len >> 8));
	out.push_back(static_cast<uint8_t>(id_len & 0xFF));
	out.push_back(static_cast<uint8_t>(type_len >> 8));
	out.push_back(static_cast<uint8_t>(type_len & 0xFF));
	out.push_back(static_cast<uint8_t>((data_len >> 24) & 0xFF));
	out.push_back(static_cast<uint8_t>((data_len >> 16) & 0xFF));
	out.push_back(static_cast<uint8_t>((data_len >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>(data_len & 0xFF));

	AppendField(out, options.data(), options.size());
	AppendField(out, id.data(), id.size());
	AppendField(out, reinterpret_cast<const uint8_t *>(type_.data()), type_.size());
	AppendField(out, data.data(), data.size());
	return out;
}

Record DecodeRecord(const uint8_t *buf, size_t len, size_t offset, size_t &next_offset) {
	if (len < offset || len - offset < HEADER_LEN) {
		throw IncompleteMessage("truncated DIME header");
	}
	const uint8_t *h = buf + offset;
	const uint8_t flags = h[0];
	const uint8_t type_byte = h[1];
	const uint16_t opt_len = static_cast<uint16_t>((h[2] << 8) | h[3]);
	const uint16_t id_len = static_cast<uint16_t>((h[4] << 8) | h[5]);
	const uint16_t type_len = static_cast<uint16_t>((h[6] << 8) | h[7]);
	const uint32_t data_len = (static_cast<uint32_t>(h[8]) << 24) | (static_cast<uint32_t>(h[9]) << 16) |
							  (static_cast<uint32_t>(h[10]) << 8) | static_cast<uint32_t>(h[11]);

	const uint8_t version = static_cast<uint8_t>(flags >> 3);
	if (version != VERSION) {
		// [MS-SSAS]: "This value MUST be set to 1."
		throw ProtocolError("unsupported DIME version " + std::to_string(version) + ", expected 1");
	}

	size_t pos = offset + HEADER_LEN;
	const size_t lengths[4] = {opt_len, id_len, type_len, data_len};
	Bytes fields[4];
	for (int i = 0; i < 4; i++) {
		const size_t field_len = lengths[i];
		// Guard the addition itself: data_len is a uint32 from a remote peer, and
		// on a 32-bit size_t `pos + field_len` can wrap and pass a bounds check it
		// should fail.
		if (field_len > len || pos > len - field_len) {
			throw IncompleteMessage("truncated DIME record body");
		}
		fields[i].assign(buf + pos, buf + pos + field_len);
		pos += field_len;
		const size_t pad = Pad(field_len);
		if (pad > len - pos) {
			// The declared bytes arrived but their padding has not. This is
			// INCOMPLETE, not decoded: leaving the pad bytes in the stream makes
			// them the next message's header.
			throw IncompleteMessage("truncated DIME record padding");
		}
		pos += pad;
	}

	Record record;
	record.options = fields[0];
	record.id = fields[1];
	record.type_.assign(fields[2].begin(), fields[2].end());
	record.data = fields[3];
	record.mb = (flags & 0x04) != 0;
	record.me = (flags & 0x02) != 0;
	record.cf = (flags & 0x01) != 0;
	record.type_t = static_cast<uint8_t>(type_byte >> 4);
	next_offset = pos;
	return record;
}

Bytes EncodeMessage(const Bytes &payload, const std::string &type_) {
	Record r;
	r.data = payload;
	r.type_ = type_;
	return r.Encode();
}

DecodedMessage DecodeMessageAt(const uint8_t *buf, size_t len, size_t offset) {
	DecodedMessage out;
	bool first = true;
	size_t pos = offset;
	for (;;) {
		size_t next = 0;
		Record record = DecodeRecord(buf, len, pos, next);
		pos = next;
		if (first) {
			if (!record.mb) {
				throw ProtocolError("first DIME record does not set MB");
			}
			out.content_type = record.type_;
			out.options = record.options;
			first = false;
		}
		out.payload.insert(out.payload.end(), record.data.begin(), record.data.end());
		if (record.me) {
			break;
		}
		if (pos >= len) {
			// Incomplete, not malformed: a chunked message split at a record
			// boundary looks exactly like this and just needs more bytes.
			throw IncompleteMessage("DIME message ended without a record setting ME");
		}
	}
	out.next_offset = pos;
	return out;
}

void CheckNegotiated(const Bytes &record_options, const std::string &record_type) {
	const uint8_t first = record_options.empty() ? 0 : record_options[0];
	if (first & (OPT_REQ_SX | OPT_RESP_SX)) {
		throw NegotiationError(
			"server selected binary XML (application/sx); this client "
			"negotiates clear-text text/xml only");
	}
	if (first & (OPT_REQ_XPRESS | OPT_RESP_XPRESS)) {
		throw NegotiationError(
			"server selected XPRESS compression; this client negotiates "
			"uncompressed text/xml only");
	}
	if (!record_type.empty() && record_type != TYPE_TEXT_XML) {
		throw NegotiationError("server replied with content type '" + record_type + "', expected 'text/xml'");
	}
}

}  // namespace dime
}  // namespace xmla
