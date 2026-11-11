#pragma once
#include <stdexcept>

namespace lamport_sig {
    struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
    struct UsageError : Error { using Error::Error; };           // argumentos inválidos
    struct IoError : Error { using Error::Error; };              // arquivo ausente, falha de escrita, lock
    struct FormatError : Error { using Error::Error; };          // arquivo malformado/incompatível
    struct KeyAlreadyUsedError : Error { using Error::Error; };  // chave de uso único já consumida

}