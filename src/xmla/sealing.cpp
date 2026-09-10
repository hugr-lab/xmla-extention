#include "xmla/sealing.hpp"

#include "xmla/errors.hpp"

namespace xmla {
namespace sealing {

const uint8_t BOM[3] = {0xEF, 0xBB, 0xBF};

Bytes SealFrame(SealProvider &provider, const Bytes &payload) {
	const Sealed sealed = provider.Seal(payload);
	if (sealed.ciphertext.size() > MAX_FRAME_BODY || sealed.token.size() > MAX_FRAME_BODY) {
		// Refuse rather than truncate. A truncated frame is a valid-looking one
		// that decrypts to rubbish somewhere else.
		throw ProtocolError("frame exceeds the uint16 size fields");
	}
	const uint16_t data_size = static_cast<uint16_t>(sealed.ciphertext.size());
	const uint16_t token_size = static_cast<uint16_t>(sealed.token.size());

	Bytes out;
	out.reserve(HEADER_LEN + sealed.ciphertext.size() + sealed.token.size());
	// Little-endian, unlike the big-endian DIME header one layer down.
	out.push_back(static_cast<uint8_t>(data_size & 0xFF));
	out.push_back(static_cast<uint8_t>((data_size >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>(token_size & 0xFF));
	out.push_back(static_cast<uint8_t>((token_size >> 8) & 0xFF));
	out.insert(out.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
	out.insert(out.end(), sealed.token.begin(), sealed.token.end());
	return out;
}

Bytes SealMessage(SealProvider &provider, const Bytes &payload) {
	size_t chunk = provider.MaxChunk();
	if (chunk == 0 || chunk > MAX_FRAME_BODY) {
		chunk = MAX_FRAME_BODY;
	}

	Bytes out;
	const Bytes bom(BOM, BOM + BOM_LEN);
	const Bytes bom_frame = SealFrame(provider, bom);
	out.insert(out.end(), bom_frame.begin(), bom_frame.end());

	// An empty body still gets no frame; the BOM frame alone is a valid message.
	for (size_t start = 0; start < payload.size(); start += chunk) {
		const size_t end = (start + chunk < payload.size()) ? start + chunk : payload.size();
		const Bytes piece(payload.begin() + static_cast<long>(start), payload.begin() + static_cast<long>(end));
		const Bytes frame = SealFrame(provider, piece);
		out.insert(out.end(), frame.begin(), frame.end());
	}
	return out;
}

Bytes Unsealer::Append(const uint8_t *data, size_t size) {
	buffer_.insert(buffer_.end(), data, data + size);

	Bytes plain;
	size_t offset = 0;
	while (buffer_.size() - offset >= HEADER_LEN) {
		const size_t data_size = static_cast<size_t>(buffer_[offset]) | (static_cast<size_t>(buffer_[offset + 1]) << 8);
		const size_t token_size =
			static_cast<size_t>(buffer_[offset + 2]) | (static_cast<size_t>(buffer_[offset + 3]) << 8);
		const size_t body = offset + HEADER_LEN;
		const size_t available = buffer_.size() - body;
		if (data_size > available || token_size > available - data_size) {
			break;	// the frame has not fully arrived
		}
		const Bytes ciphertext(buffer_.begin() + static_cast<long>(body),
							   buffer_.begin() + static_cast<long>(body + data_size));
		const Bytes token(buffer_.begin() + static_cast<long>(body + data_size),
						  buffer_.begin() + static_cast<long>(body + data_size + token_size));
		offset = body + data_size + token_size;

		const Bytes piece = provider_.Unseal(ciphertext, token);
		plain.insert(plain.end(), piece.begin(), piece.end());
	}
	buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<long>(offset));

	if (bom_settled_) {
		return plain;
	}
	// The BOM was sealed as its own frame on the way out and comes back the same
	// way; strip it so callers see the document, not the preamble. Held back
	// rather than tested per frame, because "the first three bytes" is the
	// contract and a frame boundary is not guaranteed to fall there.
	head_.insert(head_.end(), plain.begin(), plain.end());
	if (head_.size() < BOM_LEN) {
		return Bytes();
	}
	bom_settled_ = true;
	if (head_[0] == BOM[0] && head_[1] == BOM[1] && head_[2] == BOM[2]) {
		head_.erase(head_.begin(), head_.begin() + BOM_LEN);
	}
	Bytes out;
	out.swap(head_);
	return out;
}

void Unsealer::Finish() {
	if (buffer_.empty()) {
		return;
	}
	// The 1-3 byte partial header is its OWN message, and always was. Folding it
	// into the loop condition drops it in silence and returns short plaintext
	// with no error.
	if (buffer_.size() < HEADER_LEN) {
		throw IncompleteMessage("sealed message ends inside a frame header");
	}
	throw IncompleteMessage("sealed frame runs past the end of the message");
}

Bytes Unsealer::Flush() {
	if (bom_settled_) {
		return Bytes();
	}
	bom_settled_ = true;
	if (head_.size() >= BOM_LEN && head_[0] == BOM[0] && head_[1] == BOM[1] && head_[2] == BOM[2]) {
		head_.erase(head_.begin(), head_.begin() + BOM_LEN);
	}
	Bytes out;
	out.swap(head_);
	return out;
}

Bytes UnsealMessage(SealProvider &provider, const Bytes &blob) {
	Unsealer unsealer(provider);
	Bytes plain = unsealer.Append(blob);
	unsealer.Finish();
	const Bytes tail = unsealer.Flush();
	plain.insert(plain.end(), tail.begin(), tail.end());
	return plain;
}

}  // namespace sealing
}  // namespace xmla
