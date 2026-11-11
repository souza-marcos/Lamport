#include "schemes/lamport.hpp"

#include <algorithm>

#include "common/errors.hpp"
#include "crypto/random.hpp"

namespace lamport_sig::schemes::lamport {

int digest_bit(const Hash256& digest, size_t i) {
    return (digest[i / 8] >> (7 - i % 8)) & 1;
}

KeyPair keygen() {
    KeyPair keys;
    const auto random = crypto::secure_random(kBits * 2 * Hash256{}.size());
    size_t offset = 0;
    for (size_t i = 0; i < kBits; ++i) {
        for (size_t bit = 0; bit < 2; ++bit) {
            auto& secret = keys.priv.sk[i][bit];
            std::copy_n(random.begin() + offset, secret.size(), secret.begin());
            offset += secret.size();
            keys.pub.pk[i][bit] = crypto::sha256_domain(
                crypto::Domain::Secret, {secret.begin(), secret.end()});
        }
    }
    return keys;
}

namespace detail {

Signature sign_raw(const PrivateKey& key, const Hash256& message_digest) {
    Signature signature;
    for (size_t i = 0; i < kBits; ++i)
        signature.reveal[i] = key.sk[i][digest_bit(message_digest, i)];
    return signature;
}

}  // namespace detail

Signature sign(PrivateKey& key, const std::vector<uint8_t>& message) {
    if (key.used) throw KeyAlreadyUsedError("chave Lamport já utilizada");
    const auto digest = crypto::sha256_domain(crypto::Domain::Message, message);
    auto signature = detail::sign_raw(key, digest);
    key.used = true;
    return signature;
}

bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig) {
    const auto digest = crypto::sha256_domain(crypto::Domain::Message, message);
    for (size_t i = 0; i < kBits; ++i) {
        const auto& secret = sig.reveal[i];
        if (crypto::sha256_domain(crypto::Domain::Secret, {secret.begin(), secret.end()}) !=
            pub.pk[i][digest_bit(digest, i)])
            return false;
    }
    return true;
}

}  // namespace lamport_sig::schemes::lamport
