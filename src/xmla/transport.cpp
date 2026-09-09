#include "xmla/transport.hpp"

#include "xmla/errors.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace xmla {

// ---------------------------------------------------------------------------
// SocketChannel
// ---------------------------------------------------------------------------

SocketChannel::SocketChannel(const std::string &host, uint16_t port, double timeout_seconds) {
	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	const std::string service = std::to_string(port);
	struct addrinfo *result = nullptr;
	if (getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0 || result == nullptr) {
		// Deliberately does not include the host: constitution I.
		throw ConnectionError("could not resolve the instance address on port " + service);
	}

	struct timeval tv;
	tv.tv_sec = static_cast<time_t>(timeout_seconds);
	tv.tv_usec = static_cast<suseconds_t>((timeout_seconds - static_cast<double>(tv.tv_sec)) * 1e6);

	for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next) {
		const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		// Both directions, before connect: FR-025 admits no unbounded wait, and a
		// connect to a filtered port is exactly where one would occur.
		::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			fd_ = fd;
			break;
		}
		::close(fd);
	}
	freeaddrinfo(result);

	if (fd_ < 0) {
		throw ConnectionError("could not connect on port " + service);
	}
}

SocketChannel::~SocketChannel() {
	Close();
}

void SocketChannel::Send(const Bytes &data) {
	if (fd_ < 0) {
		throw ConnectionError("send on a closed connection");
	}
	size_t offset = 0;
	while (offset < data.size()) {
		// MSG_NOSIGNAL where it exists: a peer that closes mid-write otherwise
		// raises SIGPIPE and takes the host process down, which for a DuckDB
		// extension means killing the user's session over a network fault.
#ifdef MSG_NOSIGNAL
		const int flags = MSG_NOSIGNAL;
#else
		const int flags = 0;
#endif
		const ssize_t n = ::send(fd_, data.data() + offset, data.size() - offset, flags);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) {
				continue;
			}
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				throw ConnectionError("timed out sending a request");
			}
			throw ConnectionError("send failed");
		}
		offset += static_cast<size_t>(n);
	}
}

Bytes SocketChannel::Recv(size_t size) {
	if (fd_ < 0) {
		throw ConnectionError("receive on a closed connection");
	}
	Bytes buf(size);
	for (;;) {
		const ssize_t n = ::recv(fd_, buf.data(), size, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				throw ConnectionError("timed out waiting for a response");
			}
			throw ConnectionError("receive failed");
		}
		buf.resize(static_cast<size_t>(n));
		return buf;
	}
}

void SocketChannel::Close() {
	if (fd_ >= 0) {
		::close(fd_);
		fd_ = -1;
	}
}

// ---------------------------------------------------------------------------
// BytesChannel
// ---------------------------------------------------------------------------

void BytesChannel::Send(const Bytes &data) {
	sent_.insert(sent_.end(), data.begin(), data.end());
}

Bytes BytesChannel::Recv(size_t size) {
	size_t want = size;
	if (chunk_ != 0 && chunk_ < want) {
		want = chunk_;
	}
	const size_t available = response_.size() - pos_;
	const size_t n = want < available ? want : available;
	Bytes out(response_.begin() + static_cast<long>(pos_), response_.begin() + static_cast<long>(pos_ + n));
	pos_ += n;
	return out;
}

void BytesChannel::Close() {
	closed_ = true;
}

void BytesChannel::Queue(const Bytes &response) {
	response_.insert(response_.end(), response.begin(), response.end());
}

// ---------------------------------------------------------------------------
// MessageStream
// ---------------------------------------------------------------------------

void MessageStream::SendMessage(const Bytes &payload, const Bytes &options) {
	dime::Record record;
	record.data = payload;
	record.options = options;
	channel_->Send(record.Encode());
}

Bytes MessageStream::ReceiveMessage() {
	for (;;) {
		bool complete = false;
		dime::DecodedMessage parsed;
		try {
			parsed = dime::DecodeMessageAt(buffer_.data(), buffer_.size(), 0);
			complete = true;
		} catch (const IncompleteMessage &) {
			// Not enough bytes yet. Every OTHER ProtocolError is malformed input
			// and propagates - discriminating on message text got this wrong for
			// chunked messages split at a record boundary.
			complete = false;
		}
		if (complete) {
			buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<long>(parsed.next_offset));
			dime::CheckNegotiated(parsed.options, parsed.content_type);
			return parsed.payload;
		}

		const Bytes chunk = channel_->Recv(65536);
		if (chunk.empty()) {
			throw ConnectionError("connection closed before a complete message arrived");
		}
		buffer_.insert(buffer_.end(), chunk.begin(), chunk.end());

		// Reclassifying "no record set ME" as incomplete is right for chunking,
		// but it also means a peer that never sets ME buffers until the
		// connection closes. Bound it, and say which of the two it was.
		if (buffer_.size() > max_buffer_) {
			throw ProtocolError("buffered " + std::to_string(buffer_.size()) +
								" bytes without a complete DIME message (limit " + std::to_string(max_buffer_) +
								"); the peer never set ME, or the stream is desynchronised");
		}
	}
}

void MessageStream::Close() {
	channel_->Close();
}

}  // namespace xmla
