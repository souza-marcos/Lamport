#pragma once

#include <cstdint>
#include <vector>

#include "schemes/wots.hpp"

namespace lamport_sig::schemes::merkle {

using crypto::Hash256;

struct PrivateKey {
    uint8_t w = 0;
    uint8_t height = 0;
    uint32_t next_index = 0;
    std::vector<wots::PrivateKey> leaves;
    std::vector<Hash256> nodes; // heap binário: raiz em 1, folhas em 2^height
};
struct PublicKey {
    uint8_t w = 0;
    uint8_t height = 0;
    Hash256 root{};
};
struct Signature {
    uint8_t w = 0;
    uint8_t height = 0;
    uint32_t leaf_index = 0;
    Hash256 pub_seed{};
    wots::Signature wots_sig;
    std::vector<Hash256> auth_path;
};
struct KeyPair {
    PrivateKey priv;
    PublicKey pub;
};

KeyPair keygen(uint8_t w, uint8_t height);
Signature sign(PrivateKey& key, const std::vector<uint8_t>& message);
bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig);

}  // namespace lamport_sig::schemes::merkle
