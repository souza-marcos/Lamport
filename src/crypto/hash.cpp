#include "crypto/hash.hpp"

#include <openssl/evp.h>
#include <stdexcept>

namespace lamport_sig::crypto {

Hash256 sha256(const uint8_t* data, size_t size) {
    Hash256 out{};
    unsigned int len = 0;
    // A mensagem já está em memória: uma chamada calcula o resumo completo.
    if (EVP_Digest(data, size, out.data(), &len, EVP_sha256(), nullptr) != 1 || len != out.size())
        throw std::runtime_error("sha256: falha ao calcular o resumo");
    return out;
}

Hash256 sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

Hash256 sha256_domain(Domain domain, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> buf;
    buf.reserve(1 + data.size());
    buf.push_back(static_cast<uint8_t>(domain));
    buf.insert(buf.end(), data.begin(), data.end());
    return sha256(buf);
}

}  // namespace lamport_sig::crypto
