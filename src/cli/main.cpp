#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/errors.hpp"
#include "crypto/hash.hpp"
#include "schemes/lamport.hpp"
#include "schemes/merkle.hpp"
#include "schemes/wots.hpp"
#include "serialization/formats.hpp"

namespace {

struct File {
    int fd;
    explicit File(const std::string& path, int flags, mode_t mode = 0)
        : fd(::open(path.c_str(), flags, mode)) {
        if (fd < 0) throw IoError(path + ": " + std::strerror(errno));
    }
    ~File() { ::close(fd); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};

Bytes read_exact(int fd, size_t expected) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) throw IoError(std::strerror(errno));
    if (!S_ISREG(st.st_mode) || st.st_size != static_cast<off_t>(expected))
        throw FormatError("tamanho ou tipo de arquivo inválido");
    Bytes data(expected);
    size_t done = 0;
    while (done < expected) {
        const auto n = ::pread(fd, data.data() + done, expected - done, done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw IoError("falha ao ler arquivo");
        done += static_cast<size_t>(n);
    }
    return data;
}

Bytes read_file(const std::string& path, size_t expected) {
    File file(path, O_RDONLY);
    return read_exact(file.fd, expected);
}

void write_exact(int fd, const Bytes& data) {
    size_t done = 0;
    while (done < data.size()) {
        const auto n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw IoError("falha ao escrever arquivo");
        done += static_cast<size_t>(n);
    }
    if (::fsync(fd) != 0) throw IoError("falha ao sincronizar arquivo");
}

void write_new(const std::string& path, const Bytes& data, mode_t mode) {
    File file(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    try {
        write_exact(file.fd, data);
    } catch (...) {
        ::unlink(path.c_str());
        throw;
    }
}

void save_keypair(const std::string& dir, const Bytes& private_data, const Bytes& public_data) {
    std::filesystem::create_directories(dir);
    const auto private_path = (std::filesystem::path(dir) / "private.key").string();
    const auto public_path = (std::filesystem::path(dir) / "public.key").string();
    write_new(private_path, private_data, 0600);
    try {
        write_new(public_path, public_data, 0644);
    } catch (...) {
        ::unlink(private_path.c_str());
        throw;
    }
}

void replace_file(const std::string& path, const Bytes& data) {
    std::string pattern = path + ".tmp.XXXXXX";
    const int fd = ::mkstemp(pattern.data());
    if (fd < 0) throw IoError("falha ao criar arquivo temporário da chave");
    bool open = true;
    try {
        write_exact(fd, data);
        const int close_result = ::close(fd);
        open = false;
        if (close_result != 0) throw IoError("falha ao fechar arquivo temporário da chave");
        if (::rename(pattern.c_str(), path.c_str()) != 0)
            throw IoError("falha ao substituir chave privada");
        const auto parent = std::filesystem::path(path).parent_path();
        File directory(parent.empty() ? "." : parent.string(), O_RDONLY | O_DIRECTORY);
        if (::fsync(directory.fd) != 0) throw IoError("falha ao sincronizar diretório da chave");
    } catch (...) {
        ::unlink(pattern.c_str());
        if (open) ::close(fd);
        throw;
    }
}

// O chamador mantém o bloqueio desde a leitura da chave até o fim da gravação.
void persist_signature(const std::string& key_path, const Bytes& private_data,
                       const std::string& output, const Bytes& signature) {
    File signature_file(output, O_WRONLY | O_CREAT | O_EXCL, 0644);
    try {
        // Grava o consumo da chave antes de disponibilizar a assinatura.
        replace_file(key_path, private_data);
        write_exact(signature_file.fd, signature);
    } catch (...) {
        ::unlink(output.c_str());
        throw;
    }
}

uint8_t parse_w(const std::string& value) {
    if (value == "4") return 4;
    if (value == "16") return 16;
    throw UsageError("--w deve ser 4 ou 16");
}

Bytes read_wots_file(const std::string& path, const char* magic, size_t base) {
    File file(path, O_RDONLY);
    uint8_t header[kWotsHeaderSize]{};
    if (::pread(file.fd, header, sizeof(header), 0) != sizeof(header))
        throw FormatError("arquivo W-OTS+ inválido");
    if (!std::equal(header, header + kMagicSize, magic))
        throw FormatError("arquivo W-OTS+ inválido");
    if (header[kWOffset] != 4 && header[kWOffset] != 16)
        throw FormatError("arquivo W-OTS+ inválido");
    return read_exact(file.fd, base + wots::chain_count(header[kWOffset]) * kHashSize);
}

uint8_t parse_height(const std::string& value) {
    if (value.size() != 1 || value[0] < '1' || value[0] > '8')
        throw UsageError("--height deve ser de 1 a 8");
    return static_cast<uint8_t>(value[0] - '0');
}

Bytes read_merkle_signature(const std::string& path) {
    File file(path, O_RDONLY);
    uint8_t header[kMerkleHeaderSize]{};
    if (::pread(file.fd, header, sizeof(header), 0) != sizeof(header))
        throw FormatError("arquivo Merkle inválido");
    if (!std::equal(header, header + kMagicSize, "MERSIG01"))
        throw FormatError("arquivo Merkle inválido");
    if (header[kWOffset] != 4 && header[kWOffset] != 16)
        throw FormatError("arquivo Merkle inválido");
    if (header[kHeightOffset] < 1) throw FormatError("arquivo Merkle inválido");
    if (header[kHeightOffset] > 8) throw FormatError("arquivo Merkle inválido");
    const auto expected = kMerkleSignatureBase + wots::chain_count(header[kWOffset]) * kHashSize
        + header[kHeightOffset] * kHashSize;
    return read_exact(file.fd, expected);
}

Bytes read_message(const std::string& path) {
    File file(path, O_RDONLY);
    struct stat st{};
    if (::fstat(file.fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        throw IoError("mensagem inválida");
    Bytes data(static_cast<size_t>(st.st_size));
    size_t done = 0;
    while (done < data.size()) {
        const auto n = ::read(file.fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw IoError("falha ao ler mensagem");
        done += static_cast<size_t>(n);
    }
    return data;
}

std::map<std::string, std::string> parse_options(int argc, char** argv) {
    std::map<std::string, std::string> options;
    if ((argc - 2) % 2 != 0) throw UsageError("opção sem valor");
    for (int i = 2; i < argc; i += 2) {
        const std::string name = argv[i];
        if (name.rfind("--", 0) != 0 || !options.emplace(name, argv[i + 1]).second)
            throw UsageError("opção inválida ou repetida: " + name);
    }
    return options;
}

std::string require(const std::map<std::string, std::string>& options, const char* name) {
    const auto it = options.find(name);
    if (it == options.end() || it->second.empty()) throw UsageError(std::string("falta ") + name);
    return it->second;
}

void check_options(const std::map<std::string, std::string>& options, size_t count,
                   const char* scheme) {
    if (options.size() != count || require(options, "--scheme") != scheme)
        throw UsageError("esquema ou opções incompatíveis com o comando");
}

void lamport_keygen(const std::map<std::string, std::string>& options) {
    check_options(options, 2, "lamport");
    const auto dir = require(options, "--out");
    const auto keys = lamport::keygen();
    save_keypair(dir, encode_private(keys.priv), encode_public(keys.pub));
}

void lamport_sign(const std::map<std::string, std::string>& options) {
    check_options(options, 4, "lamport");
    const auto key_path = require(options, "--key");
    const auto message = read_message(require(options, "--message"));
    const auto output = require(options, "--out");
    File lock_file(key_path + ".lock", O_RDWR | O_CREAT, 0600);
    if (::flock(lock_file.fd, LOCK_EX) != 0) throw IoError("falha ao bloquear chave privada");
    File key_file(key_path, O_RDONLY);
    auto private_data = read_exact(key_file.fd, kPrivateSize);
    auto key = decode_private(private_data);
    const auto signature = lamport::sign(key, message);
    persist_signature(key_path, encode_private(key), output, encode_signature(signature));
}

int lamport_verify(const std::map<std::string, std::string>& options) {
    check_options(options, 4, "lamport");
    const auto key = decode_public(read_file(require(options, "--key"), kPublicSize));
    const auto signature = decode_signature(read_file(require(options, "--signature"), kSignatureSize));
    const auto message = read_message(require(options, "--message"));
    const bool valid = lamport::verify(key, message, signature);
    std::cout << (valid ? "assinatura válida\n" : "assinatura inválida\n");
    return valid ? 0 : 1;
}

void wots_keygen(const std::map<std::string, std::string>& options) {
    check_options(options, 3, "wots+");
    const auto w = parse_w(require(options, "--w"));
    const auto dir = require(options, "--out");
    const auto keys = wots::keygen(w);
    save_keypair(dir, encode_wots_private(keys.priv), encode_wots_public(keys.pub));
}

void wots_sign(const std::map<std::string, std::string>& options) {
    check_options(options, options.count("--w") ? 5 : 4, "wots+");
    const auto key_path = require(options, "--key");
    const auto message = read_message(require(options, "--message"));
    const auto output = require(options, "--out");
    File lock_file(key_path + ".lock", O_RDWR | O_CREAT, 0600);
    if (::flock(lock_file.fd, LOCK_EX) != 0) throw IoError("falha ao bloquear chave privada");
    auto private_data = read_wots_file(key_path, "WOTPRV01", kWotsPrivateBase);
    auto key = decode_wots_private(private_data);
    if (options.count("--w") && parse_w(require(options, "--w")) != key.w)
        throw UsageError("--w incompatível com a chave");
    const auto signature = wots::sign(key, message);
    persist_signature(key_path, encode_wots_private(key), output, encode_wots_signature(signature));
}

int wots_verify(const std::map<std::string, std::string>& options) {
    check_options(options, options.count("--w") ? 5 : 4, "wots+");
    const auto key = decode_wots_public(read_wots_file(require(options, "--key"), "WOTPUB01", kWotsPublicBase));
    if (options.count("--w") && parse_w(require(options, "--w")) != key.w)
        throw UsageError("--w incompatível com a chave");
    const auto sig = decode_wots_signature(
        read_wots_file(require(options, "--signature"), "WOTSIG01", kWotsHeaderSize));
    const auto message = read_message(require(options, "--message"));
    const bool valid = wots::verify(key, message, sig);
    std::cout << (valid ? "assinatura válida\n" : "assinatura inválida\n");
    return valid ? 0 : 1;
}

void merkle_keygen(const std::map<std::string, std::string>& options) {
    check_options(options, 4, "merkle");
    const auto w = parse_w(require(options, "--w"));
    const auto height = parse_height(require(options, "--height"));
    const auto dir = require(options, "--out");
    const auto keys = merkle::keygen(w, height);
    save_keypair(dir, encode_merkle_private(keys.priv), encode_merkle_public(keys.pub));
}

void merkle_sign(const std::map<std::string, std::string>& options) {
    check_options(options, 4, "merkle");
    const auto key_path = require(options, "--key");
    const auto message = read_message(require(options, "--message"));
    const auto output = require(options, "--out");
    File lock_file(key_path + ".lock", O_RDWR | O_CREAT, 0600);
    if (::flock(lock_file.fd, LOCK_EX) != 0) throw IoError("falha ao bloquear chave privada");
    File key_file(key_path, O_RDONLY);
    uint8_t header[kMerkleHeaderSize]{};
    if (::pread(key_file.fd, header, sizeof(header), 0) != sizeof(header))
        throw FormatError("chave Merkle inválida");
    if (!std::equal(header, header + kMagicSize, "MERPRV01"))
        throw FormatError("chave Merkle inválida");
    if (header[kWOffset] != 4 && header[kWOffset] != 16) throw FormatError("chave Merkle inválida");
    if (header[kHeightOffset] < 1) throw FormatError("chave Merkle inválida");
    if (header[kHeightOffset] > 8) throw FormatError("chave Merkle inválida");
    auto private_data = read_exact(key_file.fd, merkle_private_size(header[kWOffset], header[kHeightOffset]));
    auto key = decode_merkle_private(private_data);
    const auto sig = merkle::sign(key, message);
    persist_signature(key_path, encode_merkle_private(key), output, encode_merkle_signature(sig));
}

int merkle_verify(const std::map<std::string, std::string>& options) {
    check_options(options, 4, "merkle");
    const auto key = decode_merkle_public(read_file(require(options, "--key"), kMerklePublicSize));
    const auto sig = decode_merkle_signature(
        read_merkle_signature(require(options, "--signature")));
    const auto message = read_message(require(options, "--message"));
    const bool valid = merkle::verify(key, message, sig);
    std::cout << (valid ? "assinatura válida\n" : "assinatura inválida\n");
    return valid ? 0 : 1;
}

void demo_reuse() {
    const auto keys = lamport::keygen();
    const Bytes first{'m', 'e', 'n', 's', 'a', 'g', 'e', 'm', ' ', '1'};
    const Bytes second{'m', 'e', 'n', 's', 'a', 'g', 'e', 'm', ' ', '2'};
    const auto first_digest = sha256_domain(Domain::Message, first);
    const auto second_digest = sha256_domain(Domain::Message, second);
    // Copiar a chave contorna a proteção de uso único para demonstrar o risco.
    auto first_key = keys.priv;
    auto second_key = keys.priv;
    const auto first_sig = lamport::sign(first_key, first);
    const auto second_sig = lamport::sign(second_key, second);
    size_t exposed_pairs = 0;
    for (size_t i = 0; i < lamport::kBits; ++i) {
        if (lamport::digest_bit(first_digest, i) != lamport::digest_bit(second_digest, i)) {
            ++exposed_pairs;
            if (first_sig.reveal[i] != second_sig.reveal[i])
                std::cout << "posição " << i << ": ambos os segredos revelados\n";
        }
    }
    std::cout << "pares expostos: " << exposed_pairs << " de 256\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) throw UsageError("use keygen, sign, verify ou demo");
        const std::string command = argv[1];
        if (command == "demo") {
            if (argc != 3 || std::string(argv[2]) != "lamport-reuse")
                throw UsageError("use demo lamport-reuse");
            demo_reuse();
            return 0;
        }
        const auto options = parse_options(argc, argv);
        const auto scheme = require(options, "--scheme");
        if (command == "keygen" && scheme == "lamport") lamport_keygen(options);
        else if (command == "keygen" && scheme == "wots+") wots_keygen(options);
        else if (command == "keygen" && scheme == "merkle") merkle_keygen(options);
        else if (command == "sign" && scheme == "lamport") lamport_sign(options);
        else if (command == "sign" && scheme == "wots+") wots_sign(options);
        else if (command == "sign" && scheme == "merkle") merkle_sign(options);
        else if (command == "verify" && scheme == "lamport") return lamport_verify(options);
        else if (command == "verify" && scheme == "wots+") return wots_verify(options);
        else if (command == "verify" && scheme == "merkle") return merkle_verify(options);
        else throw UsageError("comando desconhecido: " + command);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "erro: " << error.what() << '\n';
        return 2;
    }
}
