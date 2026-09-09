//===----------------------------------------------------------------------===//
// The post-authentication frame: how a sealed message is laid out on the wire.
//
// Every message after the handshake is sealed with the negotiated security
// context and wrapped in a 4-byte header. The layout is NOT in [MS-SSAS]; it was
// recovered from AdomdClient's TcpSecureStream.WriteHeader and
// TcpEncryptedStream.WriteInBlockMode (research D3, cited per the Provenance
// Boundary - a finding, not the code that revealed it):
//
//     uint16  dataSize    little-endian, the ciphertext length
//     uint16  tokenSize   little-endian, the security token length
//     bytes   ciphertext  dataSize bytes
//     bytes   token       tokenSize bytes
//
// CIPHERTEXT FIRST, TOKEN SECOND. That is the inverse of GSS-API ordering, and
// getting it backwards is silently fatal: the server closes the connection with
// no error and logs nothing. Nine framing attempts failed before this settled.
//
// Two details that are easy to miss and cost a lot to rediscover:
//
//  - The UTF-8 BOM is sealed as its OWN frame before the body, because the
//    reference client writes it through a writer whose encoding preamble is a
//    separate write. We emit it because the reference client does; whether the
//    server REQUIRES it has not been tested independently, because the exchange
//    that first worked fixed two faults at once.
//  - The hard ceiling is 65535, since dataSize is a uint16. The per-mechanism
//    chunk size is smaller and comes from the provider; smaller chunks are always
//    valid, just more frames.
//===----------------------------------------------------------------------===//
#pragma once

#include "xmla/seal_provider.hpp"

#include <cstdint>
#include <vector>

namespace xmla {
namespace sealing {

//! The UTF-8 byte order mark, sealed as its own frame ahead of every body.
extern const uint8_t BOM[3];
static const size_t BOM_LEN = 3;
static const size_t HEADER_LEN = 4;
//! dataSize and tokenSize are uint16, so this is the hard ceiling.
static const size_t MAX_FRAME_BODY = 0xFFFF;

//! Wrap one payload as a single sealed frame.
Bytes SealFrame(SealProvider &provider, const Bytes &payload);

//! Seal a whole message: the BOM as its own frame, then the body, chunked at the
//! provider's chunk size.
Bytes SealMessage(SealProvider &provider, const Bytes &payload);

//! Decrypt every frame in a sealed response and concatenate the plaintext.
//!
//! A buffer that ends mid-frame throws IncompleteMessage, never ProtocolError.
//! The transport discriminates on exactly that distinction, and conflating them
//! breaks chunked messages: a rowset larger than one read arrives split, which is
//! "read more", not "malformed". The 1-3 byte case matters as much as the rest -
//! a partial header that falls out of a loop condition is discarded in silence,
//! handing the caller short plaintext with no error at all.
Bytes UnsealMessage(SealProvider &provider, const Bytes &blob);

}  // namespace sealing
}  // namespace xmla
