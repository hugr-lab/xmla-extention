//===----------------------------------------------------------------------===//
// Socket lifecycle and message framing over it.
//
// The byte seam is the point of this file. `Channel` has three methods; the real
// implementation wraps a socket and tests supply recorded bytes. Every layer
// above therefore runs with sockets disabled (constitution III), with no stub
// server to keep in sync and no live instance required.
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/dime.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace xmla {

using Bytes = std::vector<uint8_t>;

//! A bidirectional byte stream. The seam that makes everything above testable.
class Channel {
public:
	virtual ~Channel() = default;
	virtual void Send(const Bytes &data) = 0;
	//! Returns fewer than `size` bytes freely; an empty result means the peer
	//! closed. Never blocks past the channel's deadline.
	virtual Bytes Recv(size_t size) = 0;
	virtual void Close() = 0;
};

//! A real TCP socket, with a deadline on every wait (FR-025).
class SocketChannel : public Channel {
public:
	SocketChannel(const std::string &host, uint16_t port, double timeout_seconds);
	~SocketChannel() override;

	void Send(const Bytes &data) override;
	Bytes Recv(size_t size) override;
	void Close() override;

private:
	int fd_ = -1;
};

//! A channel backed by recorded bytes. For tests and fixture replay.
class BytesChannel : public Channel {
public:
	BytesChannel() = default;
	explicit BytesChannel(Bytes response) : response_(std::move(response)) {}

	void Send(const Bytes &data) override;
	Bytes Recv(size_t size) override;
	void Close() override;

	//! Append another response, for a multi-round-trip exchange.
	void Queue(const Bytes &response);
	//! Cap how much a single Recv returns, to exercise fragmented reads.
	void SetChunkSize(size_t n) {
		chunk_ = n;
	}

	const Bytes &sent() const {
		return sent_;
	}
	bool closed() const {
		return closed_;
	}

private:
	Bytes sent_;
	Bytes response_;
	size_t pos_ = 0;
	size_t chunk_ = 0;
	bool closed_ = false;
};

//! Sends and receives whole DIME messages over a Channel.
//!
//! Holds a read buffer between calls. A peer may pack several messages into one
//! TCP segment, so consuming the whole buffer per message would silently drop
//! whatever followed - which an early version of the reference reader did.
class MessageStream {
public:
	//! Ceiling on the unparsed read buffer. DATA_LENGTH is a uint32, so a peer -
	//! or a desynchronised stream read as a header - can declare up to 4 GiB and
	//! an unbounded reader would accumulate towards it. 64 MiB is far above any
	//! real rowset and far below a memory problem.
	static const size_t DEFAULT_MAX_BUFFER = 64 * 1024 * 1024;

	explicit MessageStream(std::shared_ptr<Channel> channel, size_t max_buffer = DEFAULT_MAX_BUFFER)
		: channel_(std::move(channel)), max_buffer_(max_buffer) {}

	//! Send one DIME message. `options` carries the negotiation bits: NEGO is
	//! clear on the first record and set on every later one.
	void SendMessage(const Bytes &payload, const Bytes &options);

	//! Read one complete DIME message, honouring the record lengths.
	//!
	//! Reads are driven by the header's declared lengths rather than by waiting
	//! for the peer to go quiet, so a slow or fragmented response is assembled
	//! rather than truncated.
	Bytes ReceiveMessage();

	void Close();

private:
	std::shared_ptr<Channel> channel_;
	Bytes buffer_;
	size_t max_buffer_;
};

}  // namespace xmla
