cmake_minimum_required(VERSION 3.16)
project(lamport_sig LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(OpenSSL REQUIRED)

# Biblioteca de infraestrutura criptográfica (hash + RNG).
add_library(lamport_sig_crypto
  src/crypto/hash.cpp
  src/crypto/random.cpp
)
target_include_directories(lamport_sig_crypto PUBLIC include)
target_link_libraries(lamport_sig_crypto PUBLIC OpenSSL::Crypto)

add_library(lamport_sig_schemes
  src/schemes/lamport.cpp
  src/schemes/wots.cpp
  src/schemes/merkle.cpp
)
target_link_libraries(lamport_sig_schemes PUBLIC lamport_sig_crypto)

add_library(lamport_sig_serialization src/serialization/formats.cpp)
target_link_libraries(lamport_sig_serialization PUBLIC lamport_sig_schemes)

add_executable(lamport_sig src/cli/main.cpp)
target_link_libraries(lamport_sig PRIVATE lamport_sig_serialization)

add_executable(benchmark experiments/benchmark.cpp)
target_link_libraries(benchmark PRIVATE lamport_sig_serialization)

enable_testing()
add_executable(test_hash tests/test_hash.cpp)
target_link_libraries(test_hash PRIVATE lamport_sig_crypto)
add_test(NAME hash COMMAND test_hash)
add_executable(test_lamport tests/test_lamport.cpp)
target_link_libraries(test_lamport PRIVATE lamport_sig_schemes)
add_test(NAME lamport COMMAND test_lamport)
add_executable(test_wots tests/test_wots.cpp)
target_link_libraries(test_wots PRIVATE lamport_sig_schemes)
add_test(NAME wots COMMAND test_wots)
add_executable(test_merkle tests/test_merkle.cpp)
target_link_libraries(test_merkle PRIVATE lamport_sig_schemes)
add_test(NAME merkle COMMAND test_merkle)
add_test(NAME cli COMMAND bash ${CMAKE_SOURCE_DIR}/tests/test_cli.sh $<TARGET_FILE:lamport_sig>)
add_executable(test_serialization tests/test_serialization.cpp)
target_link_libraries(test_serialization PRIVATE lamport_sig_serialization)
add_test(NAME serialization COMMAND test_serialization)
