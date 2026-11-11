#include "schemes/wots.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#include "common/errors.hpp"
#include "crypto/random.hpp"

namespace lamport_sig::schemes::wots {

namespace {

int log_w(uint8_t w) {
    if (w == 4) return 2;
    if (w == 16) return 4;
    throw UsageError("W-OTS+: w deve ser 4 ou 16");
}

size_t checksum_digits(uint8_t w) { return w == 4 ? 5 : 3; }

Hash256 random_hash() {
    const auto bytes = crypto::secure_random(32);
    Hash256 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

Hash256 keyed_hash(uint8_t domain, const Hash256& key, const uint8_t* input, size_t length) {
    std::vector<uint8_t> data(32, 0);
    data[31] = domain;
    data.insert(data.end(), key.begin(), key.end());
    data.insert(data.end(), input, input + length);
    return crypto::sha256(data);
}

void put_u32(std::array<uint8_t, 32>& address, size_t offset, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        address[offset + i] = static_cast<uint8_t>(value);
        value >>= 8;
    }
}

Hash256 chain(Hash256 value, int start, int steps,
              size_t chain_index, const Hash256& seed) {
    for (int step = start; step < start + steps; ++step) {
        std::array<uint8_t, 32> address{}; // OTS address: layer, tree, type and OTS index are zero.
        // Chain index and step separate hash calls; the last field selects key (0) or mask (1).
        put_u32(address, 20, static_cast<uint32_t>(chain_index));
        put_u32(address, 24, static_cast<uint32_t>(step));
        put_u32(address, 28, 0);
        const auto key = keyed_hash(3, seed, address.data(), address.size());
        put_u32(address, 28, 1);
        const auto mask = keyed_hash(3, seed, address.data(), address.size());
        for (size_t j = 0; j < value.size(); ++j) value[j] ^= mask[j];
        value = keyed_hash(0, key, value.data(), value.size());
    }
    return value;
}

}  // namespace

size_t chain_count(uint8_t w) {
    return 256 / log_w(w) + checksum_digits(w);
}

std::vector<uint8_t> message_digits(const Hash256& digest, uint8_t w) {
    const int bits = log_w(w);
    std::vector<uint8_t> digits;
    digits.reserve(chain_count(w));
    // Increasing a message digit decreases this sum, so advancing chains alone
    // cannot produce both the new message digits and its checksum.
    unsigned checksum = 0;
    for (uint8_t byte : digest) {
        for (int shift = 8 - bits; shift >= 0; shift -= bits) {
            const auto digit = static_cast<uint8_t>((byte >> shift) & (w - 1));
            digits.push_back(digit);
            checksum += w - 1 - digit;
        }
    }
    const auto len2 = checksum_digits(w);
    const auto len1 = digits.size();
    digits.resize(len1 + len2);
    for (size_t i = len2; i > 0; --i) {
        digits[len1 + i - 1] = static_cast<uint8_t>(checksum % w);
        checksum /= w;
    }
    return digits;
}

KeyPair keygen(uint8_t w) {
    const auto count = chain_count(w);
    KeyPair pair;
    pair.priv.w = pair.pub.w = w;
    pair.priv.pub_seed = pair.pub.pub_seed = random_hash();
    pair.priv.sk.reserve(count);
    pair.pub.pk.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        pair.priv.sk.push_back(random_hash());
        pair.pub.pk.push_back(chain(pair.priv.sk.back(), 0, w - 1, i, pair.pub.pub_seed));
    }
    return pair;
}

Signature sign(PrivateKey& key, const std::vector<uint8_t>& message) {
    if (key.used) throw KeyAlreadyUsedError("chave W-OTS+ já utilizada");
    const auto digits = message_digits(crypto::sha256(message), key.w);
    if (key.sk.size() != digits.size()) throw FormatError("chave W-OTS+ inválida");
    Signature sig;
    sig.w = key.w;
    sig.reveal.reserve(digits.size());
    for (size_t i = 0; i < digits.size(); ++i)
        sig.reveal.push_back(chain(key.sk[i], 0, digits[i], i, key.pub_seed));
    key.used = true;
    return sig;
}

PublicKey recover_public(const Hash256& pub_seed, const std::vector<uint8_t>& message,
                         const Signature& sig) {
    if (sig.w != 4 && sig.w != 16) throw FormatError("parâmetro W-OTS+ inválido");
    if (sig.reveal.size() != chain_count(sig.w)) throw FormatError("assinatura W-OTS+ inválida");
    PublicKey pub;
    pub.w = sig.w;
    pub.pub_seed = pub_seed;
    const auto digits = message_digits(crypto::sha256(message), sig.w);
    pub.pk.reserve(digits.size());
    for (size_t i = 0; i < digits.size(); ++i) {
        pub.pk.push_back(chain(sig.reveal[i], digits[i], sig.w - 1 - digits[i],
                               i, pub_seed));
    }
    return pub;
}

bool verify(const PublicKey& pub, const std::vector<uint8_t>& message, const Signature& sig) {
    if (pub.w != sig.w) return false;
    if (pub.w != 4 && pub.w != 16) return false;
    if (pub.pk.size() != chain_count(pub.w)) return false;
    if (sig.reveal.size() != pub.pk.size()) return false;
    return recover_public(pub.pub_seed, message, sig).pk == pub.pk;
}

}  // namespace lamport_sig::schemes::wots
