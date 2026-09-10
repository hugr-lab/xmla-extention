#include "xmla/transport.hpp"

#include "xmla/errors.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
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

	// SO_SNDTIMEO does NOT bound connect() on a blocking socket, on Linux or on
	// the BSDs -- it applies to send operations only. An earlier version of this
	// code set both timeouts here and claimed in a comment that this covered
	// "a connect to a filtered port", which is precisely the case it did not
	// cover: connect() on a blocking fd runs to the kernel's SYN-retry limit
	// (~130 s on Linux with tcp_syn_retries=6) regardless, and with AF_UNSPEC
	// and a dual-stack name that cost is paid PER ADDRESS. FR-025 admits no
	// unbounded wait, so the connect is made non-blocking and bounded explicitly.
	//
	// The deadline is shared across addresses rather than restarted for each, so
	// a name resolving to several unreachable addresses still returns within the
	// caller's timeout instead of a multiple of it.
	const auto deadline =
		std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<long long>(timeout_seconds * 1000.0));

	for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next) {
		const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		// For the send/recv that follow once the connection is up.
		::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		const int flags = ::fcntl(fd, F_GETFL, 0);
		if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			::close(fd);
			continue;
		}

		bool connected = false;
		if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			connected = true;
		} else if (errno == EINPROGRESS) {
			for (;;) {
				const auto now = std::chrono::steady_clock::now();
				if (now >= deadline) {
					break;
				}
				const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
				struct pollfd pfd;
				pfd.fd = fd;
				pfd.events = POLLOUT;
				pfd.revents = 0;
				const int ready = ::poll(&pfd, 1, static_cast<int>(remaining));
				if (ready < 0) {
					if (errno == EINTR) {
						continue;  // a signal, not a decision
					}
					break;
				}
				if (ready == 0) {
					break;	// the deadline expired
				}
				// poll() reporting writable does NOT mean the connect succeeded;
				// a refused connection is also writable. SO_ERROR is the answer.
				int err = 0;
				socklen_t len = sizeof(err);
				if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
					connected = true;
				}
				break;
			}
		}

		if (connected) {
			// Back to blocking, so SO_RCVTIMEO/SO_SNDTIMEO govern the session.
			::fcntl(fd, F_SETFL, flags);
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

void MessageStream::Fill() {
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

void MessageStream::ReceiveRecord(Bytes &payload, bool &more) {
	if (desynchronised_) {
		throw ProtocolError("the message stream was abandoned part-way and cannot be read again");
	}
	for (;;) {
		size_t next = 0;
		try {
			dime::Record record = dime::DecodeRecord(buffer_.data(), buffer_.size(), 0, next);
			buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<long>(next));
			if (!in_message_) {
				if (!record.mb) {
					throw ProtocolError("first DIME record does not set MB");
				}
				dime::CheckNegotiated(record.options, record.type_);
				in_message_ = true;
			}
			payload.swap(record.data);
			more = !record.me;
			if (record.me) {
				in_message_ = false;
			}
			return;
		} catch (const IncompleteMessage &) {
			// Not enough bytes yet. Every OTHER ProtocolError is malformed input
			// and propagates - discriminating on message text got this wrong for
			// chunked messages split at a record boundary.
		}
		Fill();
	}
}

void MessageStream::AbandonMessage() {
	if (!in_message_) {
		return;
	}
	in_message_ = false;
	desynchronised_ = true;
	buffer_.clear();
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

		Fill();
	}
}

void MessageStream::Close() {
	channel_->Close();
}

}  // namespace xmla
