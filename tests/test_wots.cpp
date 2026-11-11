#include <cstdio>
#include <cstdlib>
#include <vector>

#include "common/errors.hpp"
#include "schemes/wots.hpp"

using namespace lamport_sig::schemes::wots;

static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "FALHOU %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                            \
        }                                                                          \
    } while (0)

int main() {
    for (uint8_t w : {4, 16}) {
        CHECK(chain_count(w) == (w == 4 ? 133u : 67u));
        lamport_sig::crypto::Hash256 zero{};
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
        catch (const lamport_sig::KeyAlreadyUsedError&) { rejected_reuse = true; }
        CHECK(rejected_reuse);
    }
    if (failures == 0) std::puts("test_wots: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
