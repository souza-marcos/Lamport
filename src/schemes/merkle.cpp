#include "schemes/merkle.hpp"

#include <utility>

#include "common/errors.hpp"

namespace lamport_sig::schemes::merkle {

namespace {

Hash256 leaf_hash(const wots::PublicKey& key) {
    std::vector<uint8_t> data;
    data.reserve(1 + 32 + key.pk.size() * 32);
    data.push_back(key.w);
    data.insert(data.end(), key.pub_seed.begin(), key.pub_seed.end());
    for (const auto& element : key.pk)
        data.insert(data.end(), element.begin(), element.end());
    return crypto::sha256_domain(crypto::Domain::Leaf, data);
}

Hash256 node_hash(const Hash256& left, const Hash256& right) {
    std::vector<uint8_t> data;
    data.reserve(64);
    data.insert(data.end(), left.begin(), left.end());
    data.insert(data.end(), right.begin(), right.end());
    return crypto::sha256_domain(crypto::Domain::Node, data);
}

}  // namespace

KeyPair keygen(uint8_t w, uint8_t height) {
    if (height < 1 || height > 8) throw UsageError("altura Merkle deve ser de 1 a 8");
    const size_t leaf_count = size_t{1} << height;
    KeyPair pair;
    pair.priv.w = pair.pub.w = w;
    pair.priv.height = pair.pub.height = height;
    pair.priv.leaves.reserve(leaf_count);
    pair.priv.nodes.resize(2 * leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        auto leaf = wots::keygen(w);
        pair.priv.nodes[leaf_count + i] = leaf_hash(leaf.pub);
        pair.priv.leaves.push_back(std::move(leaf.priv));
    }
    for (size_t i = leaf_count - 1; i > 0; --i)
        pair.priv.nodes[i] = node_hash(pair.priv.nodes[2 * i], pair.priv.nodes[2 * i + 1]);
    pair.pub.root = pair.priv.nodes[1];
    return pair;
}

Signature sign(PrivateKey& key, const std::vector<uint8_t>& message) {
    if (key.height < 1 || key.height > 8 || (key.w != 4 && key.w != 16))
        throw FormatError("parâmetros Merkle inválidos");
    const size_t leaf_count = size_t{1} << key.height;
    if (key.next_index >= leaf_count) throw KeyAlreadyUsedError("folhas Merkle esgotadas");
    if (key.leaves.size() != leaf_count || key.nodes.size() != 2 * leaf_count)
        throw FormatError("chave Merkle inválida");
    Signature sig;
    sig.w = key.w;
    sig.height = key.height;
    sig.leaf_index = key.next_index;
    auto& leaf = key.leaves[key.next_index];
    sig.pub_seed = leaf.pub_seed;
    sig.wots_sig = wots::sign(leaf, message);
    size_t node = leaf_count + key.next_index;
    // No vetor da árvore, inverter o último bit do índice seleciona o irmão.
    // O caminho guarda esses irmãos da folha em direção à raiz.
    while (node > 1) {
        sig.auth_path.push_back(key.nodes[node ^ 1]);
        node /= 2;
    }
    ++key.next_index;
    return sig;
}

bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig) {
    if (pub.height < 1 || pub.height > 8) return false;
    if (pub.w != 4 && pub.w != 16) return false;
    if (pub.w != sig.w) return false;
    if (pub.height != sig.height) return false;
    if (sig.leaf_index >= (uint32_t{1} << pub.height)) return false;
    if (sig.auth_path.size() != pub.height) return false;
    if (sig.wots_sig.w != pub.w) return false;
    if (sig.wots_sig.reveal.size() != wots::chain_count(pub.w)) return false;
    auto value = leaf_hash(wots::recover_public(sig.pub_seed, message, sig.wots_sig));
    uint32_t index = sig.leaf_index;
    for (const auto& sibling : sig.auth_path) {
        // Índice ímpar indica filho direito: o irmão deve ficar à esquerda.
        value = index & 1 ? node_hash(sibling, value) : node_hash(value, sibling);
        index >>= 1;
    }
    return value == pub.root;
}

}  // namespace lamport_sig::schemes::merkle
