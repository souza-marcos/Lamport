#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.hpp"

namespace wots {


struct PrivateKey {
    uint8_t w = 0;
    Hash256 pub_seed{};
    std::vector<Hash256> sk;
    bool used = false;
};
struct PublicKey {
    uint8_t w = 0;
    Hash256 pub_seed{};
    std::vector<Hash256> pk;
};
struct Signature {
    uint8_t w = 0;
    std::vector<Hash256> reveal;
};
struct KeyPair {
    PrivateKey priv;
    PublicKey pub;
};

size_t chain_count(uint8_t w);
std::vector<uint8_t> message_digits(const Hash256& digest, uint8_t w);
KeyPair keygen(uint8_t w);
Signature sign(PrivateKey& key, const std::vector<uint8_t>& message);
PublicKey recover_public(const Hash256& pub_seed, const std::vector<uint8_t>& message,
                         const Signature& sig);
bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig);

}  // namespace wots
