#include "crypto/random.hpp"

#include <openssl/rand.h>

#include <limits>
#include <stdexcept>

namespace lamport_sig::crypto {

std::vector<uint8_t> secure_random(size_t size) {
    if (size > static_cast<size_t>(std::numeric_limits<int>::max()))
        throw std::runtime_error("secure_random: tamanho solicitado excede o limite do OpenSSL");

    std::vector<uint8_t> out(size);
    if (size == 0) return out;
    if (RAND_bytes(out.data(), static_cast<int>(size)) != 1)
        throw std::runtime_error("secure_random: fonte de aleatoriedade falhou");
    return out;
}

}  // namespace lamport_sig::crypto
