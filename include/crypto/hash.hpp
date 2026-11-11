#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace lamport_sig::crypto {

// Representação comum de um digest SHA-256: 32 bytes.
using Hash256 = std::array<uint8_t, 32>;

// Hash SHA-256 de uma sequência de bytes. Lança std::runtime_error em falha do backend.
Hash256 sha256(const std::vector<uint8_t>& data);
Hash256 sha256(const uint8_t* data, size_t len);

enum class Domain : uint8_t {
    Message = 0x00,  // digest da mensagem a ser assinada
    Secret = 0x01,  // hash de elemento secreto (chave pública Lamport)
    Leaf = 0x02,    // chave pública W-OTS+ em uma folha Merkle
    Node = 0x03,    // par de nós internos Merkle
};

// SHA-256(domain || data).
Hash256 sha256_domain(Domain domain, const std::vector<uint8_t>& data);

}  // namespace lamport_sig::crypto
