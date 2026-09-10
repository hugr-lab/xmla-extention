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
	//! Bytes queued but never read. A test asserts on this to show that a scan
	//! that stopped early really did leave the rest of the response on the wire,
	//! rather than reading it and discarding it.
	size_t unread() const {
		return response_.size() - pos_;
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

	//! Read the NEXT RECORD of the message being received, blocking only until
	//! that record has arrived.
	//!
	//! `more` comes back false on the record that carries ME - that record's data
	//! is still in `payload`, so the loop shape is do/while and not while. Said
	//! with two out-parameters rather than a bool return because "false" would
	//! have to mean "here is the last payload" and that reads as "no payload".
	//!
	//! This is what makes a streaming read possible: ReceiveMessage cannot
	//! return until the peer sets ME, so a caller that wants the first rows of a
	//! large rowset would otherwise still wait for the last of them.
	//!
	//! The negotiation check runs on the FIRST record of each message, exactly
	//! as the whole-message path does it.
	void ReceiveRecord(Bytes &payload, bool &more);

	//! Drop the current message's remaining records without decoding them.
	//!
	//! Not "read them and throw them away": abandoning a response means the rest
	//! of it is never wanted, and reading it would defeat the point. The
	//! connection is unusable afterwards and the caller must close it — which is
	//! why this says `Abandon` and not `Skip`.
	void AbandonMessage();

	void Close();

private:
	std::shared_ptr<Channel> channel_;
	Bytes buffer_;
	size_t max_buffer_;
	//! True between the first record of a message and the one that sets ME.
	bool in_message_ = false;
	//! Set when a message was abandoned part-way; every later read refuses.
	bool desynchronised_ = false;

	//! Read until `buffer_` holds at least one more byte, or throw.
	void Fill();
};

}  // namespace xmla
