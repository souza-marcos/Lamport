// Testes da infraestrutura criptográfica (Parte 1): SHA-256, separação de domínio e RNG.
#include <cstdio>
#include <cstdlib>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/hash.hpp"
#include "crypto/random.hpp"



static int failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "FALHOU %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                            \
        }                                                                          \
    } while (0)

static std::string hex(const Hash256& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : h) { s += d[b >> 4]; s += d[b & 15]; }
    return s;
}
static std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

int main() {
    // Vetores oficiais (FIPS 180-4 / NIST).
    CHECK(hex(sha256({})) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hex(sha256(bytes("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hex(sha256(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(hex(sha256(std::vector<uint8_t>(1000000, 'a'))) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    // Tamanho fixo e determinismo, em vários tamanhos de entrada.
    for (size_t n : {0u, 1u, 55u, 56u, 63u, 64u, 65u, 127u, 128u, 4096u}) {
        std::vector<uint8_t> m(n, 0x5a);
        Hash256 a = sha256(m), b = sha256(m);
        CHECK(a.size() == 32);
        CHECK(a == b);
    }
    CHECK(sha256(bytes("abc")) != sha256(bytes("abd")));
    CHECK(sha256_domain(Domain::Message, bytes("abc")) !=
          sha256_domain(Domain::Secret, bytes("abc")));
    CHECK(sha256_domain(Domain::Leaf, bytes("abc")) !=
          sha256_domain(Domain::Node, bytes("abc")));

    // RNG: tamanho correto (inclusive zero), saídas distintas.
    for (size_t n : {0u, 1u, 16u, 32u, 1024u, 65536u}) CHECK(secure_random(n).size() == n);
    CHECK(secure_random(32) != secure_random(32));
    std::set<std::vector<uint8_t>> seen;
    for (int i = 0; i < 100; ++i) seen.insert(secure_random(32));
    CHECK(seen.size() == 100);

    // Tratamento de erro: tamanho impossível lança exceção em vez de travar.
    bool threw = false;
    try { 
        secure_random(static_cast<size_t>(1) << 40); 
    } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw);

    if (failures == 0) std::puts("test_hash: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
