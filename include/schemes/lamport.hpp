#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/hash.hpp"

namespace lamport_sig::schemes::lamport {

using crypto::Hash256;

constexpr size_t kBits = 256;
using ElementPairs = std::array<std::array<Hash256, 2>, kBits>;  // [posição][bit]

struct PrivateKey {
    ElementPairs sk{};   // s_{i,0}, s_{i,1}
    bool used = false;   // chave de uso único: true depois de assinar
};
struct PublicKey {
    ElementPairs pk{};   // H(s_{i,0}), H(s_{i,1})
};
struct Signature {
    std::array<Hash256, kBits> reveal{};  // s_{i, m_i}
};
struct KeyPair {
    PrivateKey priv;
    PublicKey pub;
};

int digest_bit(const Hash256& digest, size_t i);

KeyPair keygen();

// Assina e CONSOME a chave (key.used = true). Lança KeyAlreadyUsedError se já estiver usada.
Signature sign(PrivateKey& key, const std::vector<uint8_t>& message);

bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig);

namespace detail {
// Assinatura "crua": não verifica nem altera `used`. Existe somente para a demonstração.
Signature sign_raw(const PrivateKey& key, const Hash256& message_digest);
}  // namespace detail

}  // namespace lamport_sig::schemes::lamport
