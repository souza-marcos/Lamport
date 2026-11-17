#include "schemes/lamport.hpp"

#include <algorithm>

#include "common/errors.hpp"
#include "crypto/random.hpp"

namespace lamport {

int digest_bit(const Hash256& digest, size_t i) {
    constexpr size_t bits_per_byte = 8;
    const size_t byte_index = i / bits_per_byte;
    const size_t bit_index_from_left = i % bits_per_byte;
    const size_t shift = bits_per_byte - 1 - bit_index_from_left;
    return (digest[byte_index] >> shift) & 1;
}

KeyPair keygen() {
    KeyPair keys;
    const auto random = secure_random(kBits * 2 * Hash256{}.size());
    size_t offset = 0;
    for (size_t i = 0; i < kBits; i++) {
        for (size_t bit : {0, 1}) {
            auto& secret = keys.priv.sk[i][bit];
            
            // Preenchendo a chave privada com os bits aleatórios.
            std::copy_n(random.begin() + offset, secret.size(), secret.begin());

            offset += secret.size();
            keys.pub.pk[i][bit] = sha256_domain(
                Domain::Secret, {secret.begin(), secret.end()});
        }
    }
    return keys;
}

Signature sign(PrivateKey& key, const std::vector<uint8_t>& message) {
    if (key.used) throw KeyAlreadyUsedError("chave Lamport já utilizada");
    const auto digest = sha256_domain(Domain::Message, message);
    Signature signature;
    for (size_t i = 0; i < kBits; ++i)
        signature.reveal[i] = key.sk[i][digest_bit(digest, i)];
    key.used = true;
    return signature;
}

bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig) {
    const auto digest = sha256_domain(Domain::Message, message);
    for (size_t i = 0; i < kBits; ++i) {
        const auto& secret = sig.reveal[i];
        if (sha256_domain(Domain::Secret, {secret.begin(), secret.end()}) !=
            pub.pk[i][digest_bit(digest, i)])
            return false;
    }
    return true;
}

}  // namespace lamport
