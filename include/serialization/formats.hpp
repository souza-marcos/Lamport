#pragma once

#include <cstddef>
#include <vector>
#include "schemes/lamport.hpp"
#include "schemes/wots.hpp"
#include "schemes/merkle.hpp"


// Formato: docs/formatos_binarios.md. A escrita recebe objetos válidos;
// a leitura valida o cabeçalho e o tamanho antes de acessar os campos.
using Bytes = std::vector<uint8_t>;
constexpr size_t kMagicSize = 8;
constexpr size_t kHashSize = 32;
constexpr size_t kWOffset = kMagicSize;
constexpr size_t kLamportPrivateHeaderSize = kMagicSize + 1;
constexpr size_t kWotsHeaderSize = kMagicSize + 1;
constexpr size_t kWotsPrivateHeaderSize = kWotsHeaderSize + 1;
constexpr size_t kWotsPrivateBase = kWotsPrivateHeaderSize + kHashSize;
constexpr size_t kWotsPublicBase = kWotsHeaderSize + kHashSize;
constexpr size_t kHeightOffset = kMagicSize + 1;
constexpr size_t kMerkleHeaderSize = kMagicSize + 2;
constexpr size_t kMerklePrivateBase = kMerkleHeaderSize + 4;
constexpr size_t kMerklePublicSize = kMerkleHeaderSize + kHashSize;
constexpr size_t kMerkleSignatureBase = kMerklePrivateBase + kHashSize;
constexpr size_t kPrivateSize = kLamportPrivateHeaderSize + lamport::kBits * 2 * kHashSize;
constexpr size_t kPublicSize = kMagicSize + lamport::kBits * 2 * kHashSize;
constexpr size_t kSignatureSize = kMagicSize + lamport::kBits * kHashSize;

Bytes encode_private(const lamport::PrivateKey& key);
lamport::PrivateKey decode_private(const Bytes& data);
Bytes encode_public(const lamport::PublicKey& key);
lamport::PublicKey decode_public(const Bytes& data);
Bytes encode_signature(const lamport::Signature& signature);
lamport::Signature decode_signature(const Bytes& data);
Bytes encode_wots_private(const wots::PrivateKey& key);
wots::PrivateKey decode_wots_private(const Bytes& data);
Bytes encode_wots_public(const wots::PublicKey& key);
wots::PublicKey decode_wots_public(const Bytes& data);
Bytes encode_wots_signature(const wots::Signature& sig);
wots::Signature decode_wots_signature(const Bytes& data);
size_t merkle_private_size(uint8_t w, uint8_t height);
Bytes encode_merkle_private(const merkle::PrivateKey& key);
merkle::PrivateKey decode_merkle_private(const Bytes& data);
Bytes encode_merkle_public(const merkle::PublicKey& key);
merkle::PublicKey decode_merkle_public(const Bytes& data);
Bytes encode_merkle_signature(const merkle::Signature& sig);
merkle::Signature decode_merkle_signature(const Bytes& data);
