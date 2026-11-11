#include <cstdio>
#include <cstdlib>
#include <vector>

#include "common/errors.hpp"
#include "schemes/merkle.hpp"

using namespace lamport_sig::schemes::merkle;

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
        auto keys = keygen(w, 2);
        for (uint32_t i = 0; i < 4; ++i) {
            const std::vector<uint8_t> message{'m', static_cast<uint8_t>('0' + i)};
            auto sig = sign(keys.priv, message);
            CHECK(sig.leaf_index == i);
            CHECK(sig.auth_path.size() == 2);
            CHECK(verify(keys.pub, message, sig));

            auto changed_message = message;
            changed_message[0] ^= 1;
            CHECK(!verify(keys.pub, changed_message, sig));
            auto changed_sig = sig;
            changed_sig.auth_path[0][0] ^= 1;
            CHECK(!verify(keys.pub, message, changed_sig));
            changed_sig = sig;
            changed_sig.leaf_index ^= 1;
            CHECK(!verify(keys.pub, message, changed_sig));
            changed_sig = sig;
            changed_sig.wots_sig.reveal[0][0] ^= 1;
            CHECK(!verify(keys.pub, message, changed_sig));
        }
        CHECK(keys.priv.next_index == 4);
        bool exhausted = false;
        try { sign(keys.priv, {'x'}); }
        catch (const lamport_sig::KeyAlreadyUsedError&) { exhausted = true; }
        CHECK(exhausted);
        auto other = keygen(w, 1);
        CHECK(other.pub.root != keys.pub.root);
    }
    if (failures == 0) std::puts("test_merkle: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
