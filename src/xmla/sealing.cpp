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

Bytes UnsealMessage(SealProvider &provider, const Bytes &blob) {
	Bytes plain;
	size_t offset = 0;
	while (offset < blob.size()) {
		// The 1-3 byte partial header is checked FIRST and explicitly. Folding it
		// into the loop condition drops it in silence and returns short plaintext
		// with no error.
		if (blob.size() - offset < HEADER_LEN) {
			throw IncompleteMessage("sealed message ends inside a frame header");
		}
		const size_t data_size = static_cast<size_t>(blob[offset]) | (static_cast<size_t>(blob[offset + 1]) << 8);
		const size_t token_size = static_cast<size_t>(blob[offset + 2]) | (static_cast<size_t>(blob[offset + 3]) << 8);
		offset += HEADER_LEN;

		const size_t remaining = blob.size() - offset;
		if (data_size > remaining || token_size > remaining - data_size) {
			throw IncompleteMessage("sealed frame runs past the end of the message");
		}
		const Bytes ciphertext(blob.begin() + static_cast<long>(offset),
							   blob.begin() + static_cast<long>(offset + data_size));
		const Bytes token(blob.begin() + static_cast<long>(offset + data_size),
						  blob.begin() + static_cast<long>(offset + data_size + token_size));
		offset += data_size + token_size;

		const Bytes piece = provider.Unseal(ciphertext, token);
		plain.insert(plain.end(), piece.begin(), piece.end());
	}

	// The BOM was sealed as its own frame on the way out and comes back the same
	// way; strip it so callers see the document, not the preamble.
	if (plain.size() >= BOM_LEN && plain[0] == BOM[0] && plain[1] == BOM[1] && plain[2] == BOM[2]) {
		plain.erase(plain.begin(), plain.begin() + BOM_LEN);
	}
	return plain;
}

}  // namespace sealing
}  // namespace xmla
