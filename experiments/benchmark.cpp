#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <vector>

#include "serialization/formats.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using Bytes = std::vector<uint8_t>;
namespace lamport = lamport_sig::schemes::lamport;
namespace wots = lamport_sig::schemes::wots;
namespace merkle = lamport_sig::schemes::merkle;
using namespace lamport_sig::serialization;
constexpr int kRuns = 10;

double milliseconds(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

// Uma linha por amostra permite calcular média e dispersão depois da execução.
void print(const char* scheme, int w, int height, int run, size_t private_bytes,
           size_t public_bytes, size_t signature_bytes,
           Clock::time_point start, Clock::time_point after_keygen,
           Clock::time_point after_sign, Clock::time_point after_verify) {
    std::printf("%s,%d,%d,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f\n",
                scheme, w, height, run, private_bytes, public_bytes, signature_bytes,
                milliseconds(start, after_keygen), milliseconds(after_keygen, after_sign),
                milliseconds(after_sign, after_verify));
}

void lamport_benchmark(const Bytes& message) {
    for (int run = 1; run <= kRuns; ++run) {
        const auto start = Clock::now();
        auto keys = lamport::keygen();
        const auto after_keygen = Clock::now();
        const auto sig = lamport::sign(keys.priv, message);
        const auto after_sign = Clock::now();
        const bool valid = lamport::verify(keys.pub, message, sig);
        const auto after_verify = Clock::now();
        if (!valid) throw std::runtime_error("benchmark: assinatura Lamport inválida");
        // Mede os arquivos reais; a serialização fica fora dos tempos dos algoritmos.
        print("lamport", 0, 0, run, encode_private(keys.priv).size(),
              encode_public(keys.pub).size(), encode_signature(sig).size(),
              start, after_keygen, after_sign, after_verify);
    }
}

void wots_benchmark(const Bytes& message, uint8_t w) {
    for (int run = 1; run <= kRuns; ++run) {
        const auto start = Clock::now();
        auto keys = wots::keygen(w);
        const auto after_keygen = Clock::now();
        const auto sig = wots::sign(keys.priv, message);
        const auto after_sign = Clock::now();
        const bool valid = wots::verify(keys.pub, message, sig);
        const auto after_verify = Clock::now();
        if (!valid) throw std::runtime_error("benchmark: assinatura W-OTS+ inválida");
        print("wots+", w, 0, run, encode_wots_private(keys.priv).size(),
              encode_wots_public(keys.pub).size(), encode_wots_signature(sig).size(),
              start, after_keygen, after_sign, after_verify);
    }
}

void merkle_benchmark(const Bytes& message, uint8_t w, uint8_t height) {
    for (int run = 1; run <= kRuns; ++run) {
        const auto start = Clock::now();
        auto keys = merkle::keygen(w, height);
        const auto after_keygen = Clock::now();
        const auto sig = merkle::sign(keys.priv, message);
        const auto after_sign = Clock::now();
        const bool valid = merkle::verify(keys.pub, message, sig);
        const auto after_verify = Clock::now();
        if (!valid) throw std::runtime_error("benchmark: assinatura Merkle inválida");
        print("merkle", w, height, run, encode_merkle_private(keys.priv).size(),
              encode_merkle_public(keys.pub).size(), encode_merkle_signature(sig).size(),
              start, after_keygen, after_sign, after_verify);
    }
}

}  // namespace

int main() {
    try {
        const Bytes message{'m', 'e', 'n', 's', 'a', 'g', 'e', 'm'};
        std::puts("scheme,w,height,run,private_bytes,public_bytes,signature_bytes,keygen_ms,sign_ms,verify_ms");
        lamport_benchmark(message);
        for (uint8_t w : {4, 16}) {
            wots_benchmark(message, w);
            for (uint8_t height : {2, 4, 6}) merkle_benchmark(message, w, height);
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
