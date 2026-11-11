#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "schemes/lamport.hpp"
#include "schemes/merkle.hpp"
#include "schemes/wots.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using Bytes = std::vector<uint8_t>;
constexpr int kRuns = 10;

double milliseconds(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void print(const char* scheme, int w, int height, size_t private_bytes,
           size_t public_bytes, size_t signature_bytes,
           double keygen_ms, double sign_ms, double verify_ms) {
    std::printf("%s,%d,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f\n",
                scheme, w, height, private_bytes, public_bytes, signature_bytes,
                keygen_ms / kRuns, sign_ms / kRuns, verify_ms / kRuns);
}

void lamport_benchmark(const Bytes& message) {
    double keygen_ms = 0, sign_ms = 0, verify_ms = 0;
    for (int i = 0; i < kRuns; ++i) {
        auto start = Clock::now();
        auto keys = lamport_sig::schemes::lamport::keygen();
        auto after_keygen = Clock::now();
        auto sig = lamport_sig::schemes::lamport::sign(keys.priv, message);
        auto after_sign = Clock::now();
        if (!lamport_sig::schemes::lamport::verify(keys.pub, message, sig)) std::exit(1);
        auto after_verify = Clock::now();
        keygen_ms += milliseconds(start, after_keygen);
        sign_ms += milliseconds(after_keygen, after_sign);
        verify_ms += milliseconds(after_sign, after_verify);
    }
    print("lamport", 0, 0, 9 + 512 * 32, 8 + 512 * 32, 8 + 256 * 32,
          keygen_ms, sign_ms, verify_ms);
}

void wots_benchmark(const Bytes& message, uint8_t w) {
    double keygen_ms = 0, sign_ms = 0, verify_ms = 0;
    for (int i = 0; i < kRuns; ++i) {
        auto start = Clock::now();
        auto keys = lamport_sig::schemes::wots::keygen(w);
        auto after_keygen = Clock::now();
        auto sig = lamport_sig::schemes::wots::sign(keys.priv, message);
        auto after_sign = Clock::now();
        if (!lamport_sig::schemes::wots::verify(keys.pub, message, sig)) std::exit(1);
        auto after_verify = Clock::now();
        keygen_ms += milliseconds(start, after_keygen);
        sign_ms += milliseconds(after_keygen, after_sign);
        verify_ms += milliseconds(after_sign, after_verify);
    }
    const auto chains = lamport_sig::schemes::wots::chain_count(w);
    print("wots+", w, 0, 42 + chains * 32, 41 + chains * 32, 9 + chains * 32,
          keygen_ms, sign_ms, verify_ms);
}

void merkle_benchmark(const Bytes& message, uint8_t w, uint8_t height) {
    double keygen_ms = 0, sign_ms = 0, verify_ms = 0;
    for (int i = 0; i < kRuns; ++i) {
        auto start = Clock::now();
        auto keys = lamport_sig::schemes::merkle::keygen(w, height);
        auto after_keygen = Clock::now();
        auto sig = lamport_sig::schemes::merkle::sign(keys.priv, message);
        auto after_sign = Clock::now();
        if (!lamport_sig::schemes::merkle::verify(keys.pub, message, sig)) std::exit(1);
        auto after_verify = Clock::now();
        keygen_ms += milliseconds(start, after_keygen);
        sign_ms += milliseconds(after_keygen, after_sign);
        verify_ms += milliseconds(after_sign, after_verify);
    }
    const auto chains = lamport_sig::schemes::wots::chain_count(w);
    const size_t leaves = size_t{1} << height;
    print("merkle", w, height,
          14 + leaves * (32 + chains * 32) + (2 * leaves - 1) * 32,
          42, 46 + chains * 32 + height * 32,
          keygen_ms, sign_ms, verify_ms);
}

}  // namespace

int main() {
    const Bytes message{'m', 'e', 'n', 's', 'a', 'g', 'e', 'm'};
    std::puts("scheme,w,height,private_bytes,public_bytes,signature_bytes,keygen_ms,sign_ms,verify_ms");
    lamport_benchmark(message);
    wots_benchmark(message, 4);
    wots_benchmark(message, 16);
    merkle_benchmark(message, 4, 4);
    merkle_benchmark(message, 16, 4);
}
