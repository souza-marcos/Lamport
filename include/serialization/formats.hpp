#pragma once

#include <cstddef>
#include <vector>
#include "schemes/lamport.hpp"
#include "schemes/wots.hpp"
#include "schemes/merkle.hpp"

namespace lamport_sig::serialization {

// Wire layout: docs/formatos_binarios.md. Encoders expect valid scheme objects;
// decoders validate the record header and exact length before reading fields.
using Bytes = std::vector<uint8_t>;
constexpr size_t kMagicSize = 8;
constexpr size_t kHashSize = 32;
constexpr size_t kWOffset = kMagicSize;
constexpr size_t kLamportUsedOffset = kMagicSize;
constexpr size_t kLamportPrivateHeaderSize = kMagicSize + 1;
constexpr size_t kWotsHeaderSize = kMagicSize + 1;
constexpr size_t kWotsUsedOffset = kWotsHeaderSize;
constexpr size_t kWotsPrivateHeaderSize = kWotsHeaderSize + 1;
constexpr size_t kWotsPrivateBase = kWotsPrivateHeaderSize + kHashSize;
constexpr size_t kWotsPublicBase = kWotsHeaderSize + kHashSize;
constexpr size_t kHeightOffset = kMagicSize + 1;
constexpr size_t kMerkleHeaderSize = kMagicSize + 2;
constexpr size_t kMerkleIndexOffset = kMerkleHeaderSize;
constexpr size_t kMerklePrivateBase = kMerkleHeaderSize + 4;
constexpr size_t kMerklePublicSize = kMerkleHeaderSize + kHashSize;
constexpr size_t kMerkleSignatureBase = kMerklePrivateBase + kHashSize;
constexpr size_t kPrivateSize = kLamportPrivateHeaderSize + schemes::lamport::kBits * 2 * kHashSize;
constexpr size_t kPublicSize = kMagicSize + schemes::lamport::kBits * 2 * kHashSize;
constexpr size_t kSignatureSize = kMagicSize + schemes::lamport::kBits * kHashSize;

Bytes encode_private(const schemes::lamport::PrivateKey& key);
schemes::lamport::PrivateKey decode_private(const Bytes& data);
Bytes encode_public(const schemes::lamport::PublicKey& key);
schemes::lamport::PublicKey decode_public(const Bytes& data);
Bytes encode_signature(const schemes::lamport::Signature& signature);
schemes::lamport::Signature decode_signature(const Bytes& data);
Bytes encode_wots_private(const schemes::wots::PrivateKey& key);
schemes::wots::PrivateKey decode_wots_private(const Bytes& data);
Bytes encode_wots_public(const schemes::wots::PublicKey& key);
schemes::wots::PublicKey decode_wots_public(const Bytes& data);
Bytes encode_wots_signature(const schemes::wots::Signature& sig);
schemes::wots::Signature decode_wots_signature(const Bytes& data);
void append_u32(Bytes& data, uint32_t value);
size_t merkle_private_size(uint8_t w, uint8_t height);
Bytes encode_merkle_private(const schemes::merkle::PrivateKey& key);
schemes::merkle::PrivateKey decode_merkle_private(const Bytes& data);
Bytes encode_merkle_public(const schemes::merkle::PublicKey& key);
schemes::merkle::PublicKey decode_merkle_public(const Bytes& data);
Bytes encode_merkle_signature(const schemes::merkle::Signature& sig);
schemes::merkle::Signature decode_merkle_signature(const Bytes& data);

}  // namespace lamport_sig::serialization
