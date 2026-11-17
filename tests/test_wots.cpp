#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/errors.hpp"
#include "schemes/wots.hpp"

using namespace wots;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "FALHOU %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                            \
        }                                                                          \
    } while (0)

std::string hex(const Hash256& hash) {
    const char* digits = "0123456789abcdef";
    std::string result;
    for (uint8_t byte : hash) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

void check_fixed_vector(uint8_t w) {
    // Referência calculada separadamente com hashlib, segundo a RFC 8391, seção 3.1.
    // Esses segredos fixos servem apenas ao teste, nunca à geração de chaves reais.
    PrivateKey key;
    key.w = w;
    for (size_t i = 0; i < key.pub_seed.size(); ++i) key.pub_seed[i] = i;
    Hash256 secret{};
    secret.fill(0x42);
    key.sk.assign(chain_count(w), secret);
    const std::vector<uint8_t> message{'a', 'b', 'c'};
    const auto sig = sign(key, message);
    const auto pub = recover_public(key.pub_seed, message, sig);
    CHECK(hex(sig.reveal.front()) == (w == 4
        ? "5b360e5f88cfc456cb297d4832b1cca94e0d1c7c3ecca82fe96154e07affff72"
        : "21d7dcdb6363a285975920fcdf6aa5e084b4b9c7e6beeb152b52e34078f1dc11"));
    CHECK(hex(sig.reveal.back()) == (w == 4
        ? "cb35577346b2c6aeda3897d26bd986f13bb7a426c54dcef0f66569a76ed43cae"
        : "9dca50534e33cee50637e2ed0094a0852893b9eff3bd0e6b05d7cdd9f1fb2b21"));
    CHECK(hex(pub.pk.front()) == (w == 4
        ? "01efdcc14c4c6c42b8d295f1df00af69d56640598e6093da0b1b20f154484b17"
        : "547a5b138eb73d2d6bd289428f5ab90cc3058c12812e50d8e8570d29dc2061a6"));
    CHECK(hex(pub.pk.back()) == (w == 4
        ? "cb35577346b2c6aeda3897d26bd986f13bb7a426c54dcef0f66569a76ed43cae"
        : "ed2f5fdfde31a8c7769b955b3fbaa341080a06a9a8c16f05682018d3b9d6599f"));
}

int main() {
    for (uint8_t w : {4, 16}) {
        check_fixed_vector(w);
        CHECK(chain_count(w) == (w == 4 ? 133u : 67u));
        Hash256 zero{};
        const auto digits = message_digits(zero, w);
        CHECK(digits.size() == chain_count(w));
        CHECK(digits[0] == 0);
        CHECK(digits[256 / (w == 4 ? 2 : 4) - 1] == 0);
        const size_t checksum_start = 256 / (w == 4 ? 2 : 4);
        CHECK(digits[checksum_start] == (w == 4 ? 1 : 3));
        CHECK(digits[checksum_start + 1] == (w == 4 ? 2 : 12));

        auto keys = keygen(w);
        const std::vector<uint8_t> message{'w', 'o', 't', 's'};
        const auto signature = sign(keys.priv, message);
        CHECK(keys.priv.used);
        CHECK(signature.reveal.size() == chain_count(w));
        CHECK(verify(keys.pub, message, signature));

        auto changed_message = message;
        changed_message[0] ^= 1;
        CHECK(!verify(keys.pub, changed_message, signature));
        auto changed_signature = signature;
        changed_signature.reveal[0][0] ^= 1;
        CHECK(!verify(keys.pub, message, changed_signature));
        auto other_keys = keygen(w);
        CHECK(!verify(other_keys.pub, message, signature));
        changed_signature = signature;
        changed_signature.w = w == 4 ? 16 : 4;
        CHECK(!verify(keys.pub, message, changed_signature));

        bool rejected_reuse = false;
        try { sign(keys.priv, message); }
        catch (const KeyAlreadyUsedError&) { rejected_reuse = true; }
        CHECK(rejected_reuse);
    }
    if (failures == 0) std::puts("test_wots: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
