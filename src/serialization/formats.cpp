#include "serialization/formats.hpp"

#include <algorithm>
#include "common/errors.hpp"

namespace lamport_sig::serialization {
namespace lamport = schemes::lamport;
namespace wots = schemes::wots;
namespace merkle = schemes::merkle;

namespace {

Bytes with_magic(const char* magic) { return Bytes(magic, magic + kMagicSize); }

void check_magic(const Bytes& data, const char* magic) {
    if (data.size() < kMagicSize) throw FormatError("cabeçalho truncado");
    if (!std::equal(data.begin(), data.begin() + kMagicSize, magic))
        throw FormatError("tipo ou versão de arquivo inválida");
}

void append_hash(Bytes& data, const crypto::Hash256& hash) {
    data.insert(data.end(), hash.begin(), hash.end());
}

void load_hash(const Bytes& data, size_t& offset, crypto::Hash256& hash) {
    std::copy_n(data.begin() + offset, hash.size(), hash.begin());
    offset += hash.size();
}

void check_size(const Bytes& data, size_t expected) {
    if (data.size() != expected) throw FormatError("tamanho de arquivo inválido");
}

void check_wots_header(const Bytes& data, const char* magic) {
    if (data.size() < kWotsHeaderSize) throw FormatError("cabeçalho W-OTS+ truncado");
    check_magic(data, magic);
    if (data[kWOffset] != 4 && data[kWOffset] != 16)
        throw FormatError("parâmetro W-OTS+ inválido");
}

void check_merkle_header(const Bytes& data, const char* magic) {
    if (data.size() < kMerkleHeaderSize) throw FormatError("cabeçalho Merkle truncado");
    check_wots_header(data, magic);
    if (data[kHeightOffset] < 1 || data[kHeightOffset] > 8)
        throw FormatError("altura Merkle inválida");
}

}  // namespace

Bytes encode_private(const lamport::PrivateKey& key) {
    auto data = with_magic("LAMPRV01");
    data.push_back(key.used ? 1 : 0);
    for (const auto& pair : key.sk)
        for (const auto& hash : pair) append_hash(data, hash);
    return data;
}

lamport::PrivateKey decode_private(const Bytes& data) {
    check_size(data, kPrivateSize);
    check_magic(data, "LAMPRV01");
    if (data[kLamportUsedOffset] > 1) throw FormatError("estado de chave inválido");
    lamport::PrivateKey key;
    key.used = data[kLamportUsedOffset] == 1;
    size_t offset = kLamportPrivateHeaderSize;
    for (auto& pair : key.sk)
        for (auto& hash : pair) load_hash(data, offset, hash);
    return key;
}

Bytes encode_public(const lamport::PublicKey& key) {
    auto data = with_magic("LAMPUB01");
    for (const auto& pair : key.pk)
        for (const auto& hash : pair) append_hash(data, hash);
    return data;
}

lamport::PublicKey decode_public(const Bytes& data) {
    check_size(data, kPublicSize);
    check_magic(data, "LAMPUB01");
    lamport::PublicKey key;
    size_t offset = kMagicSize;
    for (auto& pair : key.pk)
        for (auto& hash : pair) load_hash(data, offset, hash);
    return key;
}

Bytes encode_signature(const lamport::Signature& signature) {
    auto data = with_magic("LAMSIG01");
    for (const auto& hash : signature.reveal) append_hash(data, hash);
    return data;
}

lamport::Signature decode_signature(const Bytes& data) {
    check_size(data, kSignatureSize);
    check_magic(data, "LAMSIG01");
    lamport::Signature signature;
    size_t offset = kMagicSize;
    for (auto& hash : signature.reveal) load_hash(data, offset, hash);
    return signature;
}

Bytes encode_wots_private(const wots::PrivateKey& key) {
    auto data = with_magic("WOTPRV01");
    data.push_back(key.w);
    data.push_back(key.used ? 1 : 0);
    append_hash(data, key.pub_seed);
    for (const auto& hash : key.sk) append_hash(data, hash);
    return data;
}

wots::PrivateKey decode_wots_private(const Bytes& data) {
    check_wots_header(data, "WOTPRV01");
    check_size(data, kWotsPrivateBase + wots::chain_count(data[kWOffset]) * kHashSize);
    if (data[kWotsUsedOffset] > 1) throw FormatError("estado de chave W-OTS+ inválido");
    wots::PrivateKey key;
    key.w = data[kWOffset];
    key.used = data[kWotsUsedOffset] == 1;
    size_t offset = kWotsPrivateHeaderSize;
    load_hash(data, offset, key.pub_seed);
    key.sk.resize(wots::chain_count(key.w));
    for (auto& hash : key.sk) load_hash(data, offset, hash);
    return key;
}

Bytes encode_wots_public(const wots::PublicKey& key) {
    auto data = with_magic("WOTPUB01");
    data.push_back(key.w);
    append_hash(data, key.pub_seed);
    for (const auto& hash : key.pk) append_hash(data, hash);
    return data;
}

wots::PublicKey decode_wots_public(const Bytes& data) {
    check_wots_header(data, "WOTPUB01");
    check_size(data, kWotsPublicBase + wots::chain_count(data[kWOffset]) * kHashSize);
    wots::PublicKey key;
    key.w = data[kWOffset];
    size_t offset = kWotsHeaderSize;
    load_hash(data, offset, key.pub_seed);
    key.pk.resize(wots::chain_count(key.w));
    for (auto& hash : key.pk) load_hash(data, offset, hash);
    return key;
}

Bytes encode_wots_signature(const wots::Signature& sig) {
    auto data = with_magic("WOTSIG01");
    data.push_back(sig.w);
    for (const auto& hash : sig.reveal) append_hash(data, hash);
    return data;
}

wots::Signature decode_wots_signature(const Bytes& data) {
    check_wots_header(data, "WOTSIG01");
    check_size(data, kWotsHeaderSize + wots::chain_count(data[kWOffset]) * kHashSize);
    wots::Signature sig;
    sig.w = data[kWOffset];
    size_t offset = kWotsHeaderSize;
    sig.reveal.resize(wots::chain_count(sig.w));
    for (auto& hash : sig.reveal) load_hash(data, offset, hash);
    return sig;
}

void append_u32(Bytes& data, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        data.push_back(static_cast<uint8_t>(value >> shift));
}

static uint32_t load_u32(const Bytes& data, size_t& offset) {
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | data[offset++];
    return value;
}

size_t merkle_private_size(uint8_t w, uint8_t height) {
    if (height < 1 || height > 8) throw FormatError("altura Merkle inválida");
    const size_t leaves = size_t{1} << height;
    return kMerklePrivateBase + leaves * (kHashSize + wots::chain_count(w) * kHashSize)
        + (2 * leaves - 1) * kHashSize;
}

Bytes encode_merkle_private(const merkle::PrivateKey& key) {
    auto data = with_magic("MERPRV01");
    data.push_back(key.w);
    data.push_back(key.height);
    append_u32(data, key.next_index);
    for (const auto& leaf : key.leaves) {
        append_hash(data, leaf.pub_seed);
        for (const auto& hash : leaf.sk) append_hash(data, hash);
    }
    for (size_t i = 1; i < key.nodes.size(); ++i) append_hash(data, key.nodes[i]);
    return data;
}

merkle::PrivateKey decode_merkle_private(const Bytes& data) {
    check_merkle_header(data, "MERPRV01");
    check_size(data, merkle_private_size(data[kWOffset], data[kHeightOffset]));
    merkle::PrivateKey key;
    key.w = data[kWOffset];
    key.height = data[kHeightOffset];
    size_t offset = kMerkleHeaderSize;
    key.next_index = load_u32(data, offset);
    const size_t leaves = size_t{1} << key.height;
    if (key.next_index > leaves) throw FormatError("índice Merkle inválido");
    key.leaves.resize(leaves);
    for (size_t i = 0; i < leaves; ++i) {
        auto& leaf = key.leaves[i];
        leaf.w = key.w;
        leaf.used = i < key.next_index;
        load_hash(data, offset, leaf.pub_seed);
        leaf.sk.resize(wots::chain_count(key.w));
        for (auto& hash : leaf.sk) load_hash(data, offset, hash);
    }
    key.nodes.resize(2 * leaves);
    for (size_t i = 1; i < key.nodes.size(); ++i) load_hash(data, offset, key.nodes[i]);
    return key;
}

Bytes encode_merkle_public(const merkle::PublicKey& key) {
    auto data = with_magic("MERPUB01");
    data.push_back(key.w);
    data.push_back(key.height);
    append_hash(data, key.root);
    return data;
}

merkle::PublicKey decode_merkle_public(const Bytes& data) {
    check_merkle_header(data, "MERPUB01");
    check_size(data, kMerklePublicSize);
    merkle::PublicKey key;
    key.w = data[kWOffset];
    key.height = data[kHeightOffset];
    size_t offset = kMerkleHeaderSize;
    load_hash(data, offset, key.root);
    return key;
}

Bytes encode_merkle_signature(const merkle::Signature& sig) {
    auto data = with_magic("MERSIG01");
    data.push_back(sig.w);
    data.push_back(sig.height);
    append_u32(data, sig.leaf_index);
    append_hash(data, sig.pub_seed);
    for (const auto& hash : sig.wots_sig.reveal) append_hash(data, hash);
    for (const auto& hash : sig.auth_path) append_hash(data, hash);
    return data;
}

merkle::Signature decode_merkle_signature(const Bytes& data) {
    check_merkle_header(data, "MERSIG01");
    check_size(data, kMerkleSignatureBase + wots::chain_count(data[kWOffset]) * kHashSize
        + data[kHeightOffset] * kHashSize);
    merkle::Signature sig;
    sig.w = sig.wots_sig.w = data[kWOffset];
    sig.height = data[kHeightOffset];
    size_t offset = kMerkleHeaderSize;
    sig.leaf_index = load_u32(data, offset);
    load_hash(data, offset, sig.pub_seed);
    sig.wots_sig.reveal.resize(wots::chain_count(sig.w));
    for (auto& hash : sig.wots_sig.reveal) load_hash(data, offset, hash);
    sig.auth_path.resize(sig.height);
    for (auto& hash : sig.auth_path) load_hash(data, offset, hash);
    return sig;
}

}  // namespace lamport_sig::serialization
