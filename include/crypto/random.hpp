#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>


// Retorna `size` bytes de uma fonte criptograficamente segura (RAND_bytes do OpenSSL).
// Lança std::runtime_error se a fonte falhar; nunca retorna dados parciais ou previsíveis.
std::vector<uint8_t> secure_random(size_t size);

