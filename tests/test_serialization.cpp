#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include "common/errors.hpp"
#include "serialization/formats.hpp"

static int failures = 0;
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::fprintf(stderr, "FALHOU %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures; \
        } \
    } while (0)

// Valores fixos independentes das constantes usadas na implementação do formato.
Bytes fixture(const char* magic, size_t size, size_t payload) {
    Bytes data(magic, magic + 8);
    data.resize(size);
    for (size_t i = payload; i < size; ++i) data[i] = static_cast<uint8_t>(i * 37 + i / 32);
    return data;
}

void rejected(const Bytes& data, const std::function<Bytes(const Bytes&)>& roundtrip) {
    bool failed = false;
    try { roundtrip(data); } catch (const FormatError&) { failed = true; }
    CHECK(failed);
}

void check_record(const Bytes& data, const std::function<Bytes(const Bytes&)>& roundtrip) {
    CHECK(roundtrip(data) == data);
    for (size_t length : {size_t{0}, size_t{7}, size_t{8}, size_t{9}, data.size() - 1})
        rejected(Bytes(data.begin(), data.begin() + length), roundtrip);
    auto bad = data;
    bad.push_back(0);
    rejected(bad, roundtrip);
    bad = data;
    bad[0] ^= 1;
    rejected(bad, roundtrip);
}

int main() {
    auto lp = fixture("LAMPRV01", 16393, 9);
    lp[8] = 1;
    auto lamport_private = [](const Bytes& b) { return encode_private(decode_private(b)); };
    check_record(lp, lamport_private);
    const auto lk = decode_private(lp);
    CHECK(lk.used && lk.sk[0][0][0] == lp[9] && lk.sk[0][1][0] == lp[41]);
    lp[8] = 2;
    rejected(lp, lamport_private);
    check_record(fixture("LAMPUB01", 16392, 8),
                 [](const Bytes& b) { return encode_public(decode_public(b)); });
    check_record(fixture("LAMSIG01", 8200, 8),
                 [](const Bytes& b) { return encode_signature(decode_signature(b)); });

    for (uint8_t w : {4, 16}) {
        const size_t chains = w == 4 ? 133 : 67;
        auto wp = fixture("WOTPRV01", 42 + chains * 32, 10);
        wp[8] = w; wp[9] = 1;
        auto wots_private = [](const Bytes& b) { return encode_wots_private(decode_wots_private(b)); };
        check_record(wp, wots_private);
        const auto wk = decode_wots_private(wp);
        CHECK(wk.w == w && wk.used && wk.pub_seed[0] == wp[10] && wk.sk[0][0] == wp[42]);
        wp[9] = 2;
        rejected(wp, wots_private);
        for (const bool pub : {false, true}) {
            auto data = fixture(pub ? "WOTPUB01" : "WOTSIG01", (pub ? 41 : 9) + chains * 32, 9);
            data[8] = w;
            std::function<Bytes(const Bytes&)> roundtrip = [pub](const Bytes& b) {
                if (pub) return encode_wots_public(decode_wots_public(b));
                return encode_wots_signature(decode_wots_signature(b));
            };
            check_record(data, roundtrip);
            data[8] = 8;
            rejected(data, roundtrip);
        }
        // Altura 2: quatro folhas e sete nós; o nó zero não é gravado.
        auto mp = fixture("MERPRV01", 14 + 4 * (32 + chains * 32) + 7 * 32, 14);
        mp[8] = w; mp[9] = 2; mp[13] = 1;
        auto merkle_private = [](const Bytes& b) { return encode_merkle_private(decode_merkle_private(b)); };
        check_record(mp, merkle_private);
        const auto mk = decode_merkle_private(mp);
        CHECK(mk.next_index == 1 && mk.leaves[0].used && !mk.leaves[1].used);
        CHECK(mk.leaves[0].pub_seed[0] == mp[14] && mk.leaves[0].sk[0][0] == mp[46]);
        CHECK(mk.nodes[1][0] == mp[14 + 4 * (32 + chains * 32)]);
        mp[13] = 4; // Uma chave esgotada ainda é um arquivo válido.
        CHECK(decode_merkle_private(mp).next_index == 4);
        mp[10] = 1; // Em big endian, esse valor ultrapassa as quatro folhas.
        rejected(mp, merkle_private);
        for (const bool pub : {false, true}) {
            auto data = fixture(pub ? "MERPUB01" : "MERSIG01", pub ? 42 : 46 + chains * 32 + 64, pub ? 10 : 14);
            data[8] = w; data[9] = 2;
            if (!pub) {
                data[13] = 3;
                const auto sig = decode_merkle_signature(data);
                CHECK(sig.leaf_index == 3 && sig.pub_seed[0] == data[14]);
                CHECK(sig.wots_sig.reveal[0][0] == data[46]);
                CHECK(sig.auth_path[0][0] == data[46 + chains * 32]);
            }
            std::function<Bytes(const Bytes&)> roundtrip = [pub](const Bytes& b) {
                if (pub) return encode_merkle_public(decode_merkle_public(b));
                return encode_merkle_signature(decode_merkle_signature(b));
            };
            check_record(data, roundtrip);
            data[9] = 0;
            rejected(data, roundtrip);
            data[9] = 9;
            rejected(data, roundtrip);
            data[9] = 2; data[8] = 8;
            rejected(data, roundtrip);
        }
    }
    if (failures == 0) std::puts("test_serialization: OK");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
