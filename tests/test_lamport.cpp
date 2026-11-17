#include <cstdio>
#include <cstdlib>
#include <vector>

#include "common/errors.hpp"
#include "schemes/lamport.hpp"

using namespace lamport;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "FALHOU %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                            \
        }                                                                          \
    } while (0)

int main() {
    Hash256 bits{};
    bits[0] = 0x80;
    bits[31] = 0x01;
    CHECK(digest_bit(bits, 0) == 1);
    CHECK(digest_bit(bits, 1) == 0);
    CHECK(digest_bit(bits, 255) == 1);

    auto keys = keygen();
    const std::vector<uint8_t> message{'m', 'e', 's', 's', 'a', 'g', 'e'};
    const auto digest = sha256_domain(
        Domain::Message, message);
    for (size_t i = 0; i < kBits; ++i) {
        for (size_t bit = 0; bit < 2; ++bit) {
            const auto& secret = keys.priv.sk[i][bit];
            CHECK(keys.pub.pk[i][bit] == sha256_domain(
                Domain::Secret, {secret.begin(), secret.end()}));
        }
    }

    const auto signature = sign(keys.priv, message);
    CHECK(keys.priv.used);
    CHECK(verify(keys.pub, message, signature));
    for (size_t i = 0; i < kBits; ++i)
        CHECK(signature.reveal[i] == keys.priv.sk[i][digest_bit(digest, i)]);

    auto changed_message = message;
    changed_message[0] ^= 1;
    CHECK(!verify(keys.pub, changed_message, signature));

    auto changed_signature = signature;
    changed_signature.reveal[0][0] ^= 1;
    CHECK(!verify(keys.pub, message, changed_signature));

    auto other_keys = keygen();
    CHECK(!verify(other_keys.pub, message, signature));

    bool rejected_reuse = false;
    try {
        sign(keys.priv, changed_message);
    } catch (const KeyAlreadyUsedError&) {
        rejected_reuse = true;
    }
    CHECK(rejected_reuse);

    if (failures == 0) std::puts("test_lamport: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
