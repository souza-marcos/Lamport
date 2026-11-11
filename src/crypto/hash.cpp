#include "crypto/hash.hpp"

#include <openssl/evp.h>
#include <memory>
#include <stdexcept>

namespace lamport_sig::crypto {

namespace {

struct CtxDeleter {
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

/**
 * Faz o digest da mensagem usando o OpenSSL. (Usando o exemplo de https://friendlyuser.github.io/posts/tech/cpp/Using_OpenSSL_in_C++_A_Comprehensive_Guide/_
 * 
 * @returns H(data) 32 bytes
 */
Hash256 digest(const uint8_t* data, size_t data_len) {
    std::unique_ptr<EVP_MD_CTX, CtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("sha256: falha ao inicializar o contexto");

    if (data_len > 0 && EVP_DigestUpdate(ctx.get(), data, data_len) != 1)
        throw std::runtime_error("sha256: falha ao processar os dados");

    Hash256 out{};
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1 || len != out.size())
        throw std::runtime_error("sha256: falha ao finalizar o digest");
    return out;
}

}  // namespace


Hash256 sha256(const std::vector<uint8_t>& data) {
    return digest(data.data(), data.size());
}

Hash256 sha256(const uint8_t* data, size_t len) {
    return digest(data, len);
}


Hash256 sha256_domain(Domain domain, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> buf;
    buf.reserve(1 + data.size());
    buf.push_back(static_cast<uint8_t>(domain));
    buf.insert(buf.end(), data.begin(), data.end());
    return digest(buf.data(), buf.size());
}

}  // namespace lamport_sig::crypto
