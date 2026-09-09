//===----------------------------------------------------------------------===//
// A server made of bytes, not of sockets.
//
// Builds exactly what an instance would put on the wire for a given response
// document, so a test can vary EACH of the three splitting layers independently
// and then all of them at once:
//
//   1. sealed-frame chunking   (sealing)    - chunk_bytes
//   2. DIME record chunking    (dime)       - record_bytes
//   3. TCP fragmentation       (transport)  - read_bytes
//
// They compose, and getting the composition wrong corrupts large rowsets
// specifically - the case least likely to be exercised by a first test.
//===----------------------------------------------------------------------===//
#pragma once

#include "fake_provider.hpp"
#include "xmla/dime.hpp"
#include "xmla/gss_context.hpp"
#include "xmla/sealing.hpp"
#include "xmla/transport.hpp"

#include <memory>
#include <string>

namespace xmla {

//! A GSS context that completes after `legs` round trips, like a real
//! mechanism's, and hands out a provider of the requested token size.
class FakeGssContext : public GssContext {
public:
	FakeGssContext(int legs, size_t token_len, size_t max_chunk)
		: legs_(legs), token_len_(token_len), max_chunk_(max_chunk) {}

	Bytes Step(const Bytes &) override {
		step_++;
		if (step_ >= legs_) {
			complete_ = true;
		}
		// A real mechanism emits a token on every leg including the last, which
		// is exactly why the caller must fault-check the terminal response.
		return Bytes(8, static_cast<uint8_t>(step_));
	}

	bool IsComplete() const override {
		return complete_;
	}

	std::unique_ptr<SealProvider> MakeSealProvider() override {
		return std::unique_ptr<SealProvider>(new FakeSealProvider(token_len_, max_chunk_));
	}

	int steps() const {
		return step_;
	}

private:
	int legs_;
	size_t token_len_;
	size_t max_chunk_;
	int step_ = 0;
	bool complete_ = false;
};

//! Wrap a payload in DIME records of at most `record_bytes` each, chunked with
//! MB/CF/ME the way a server splitting a large response does.
inline Bytes WrapInDimeRecords(const Bytes &payload, size_t record_bytes) {
	if (record_bytes == 0 || payload.size() <= record_bytes) {
		return dime::EncodeMessage(payload);
	}
	Bytes out;
	size_t offset = 0;
	bool first = true;
	while (offset < payload.size()) {
		const size_t take = std::min(record_bytes, payload.size() - offset);
		const bool last = (offset + take >= payload.size());
		dime::Record r;
		r.data.assign(payload.begin() + static_cast<long>(offset), payload.begin() + static_cast<long>(offset + take));
		r.mb = first;
		r.me = last;
		r.cf = !last;
		// Only the FIRST record carries the type and options; the continuations
		// carry neither, which is what a chunked DIME message looks like.
		if (!first) {
			r.type_.clear();
			r.options.clear();
		}
		const Bytes encoded = r.Encode();
		out.insert(out.end(), encoded.begin(), encoded.end());
		offset += take;
		first = false;
	}
	return out;
}

//! The full wire form of one sealed response.
inline Bytes SealedResponseWire(SealProvider &provider, const std::string &document, size_t record_bytes) {
	const Bytes body(document.begin(), document.end());
	const Bytes sealed = sealing::SealMessage(provider, body);
	return WrapInDimeRecords(sealed, record_bytes);
}

//! An unsealed response, as the handshake legs use.
inline Bytes PlainResponseWire(const std::string &document, size_t record_bytes) {
	const Bytes body(document.begin(), document.end());
	return WrapInDimeRecords(body, record_bytes);
}

}  // namespace xmla
