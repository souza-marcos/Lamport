# lamport_sig — Ferramenta de Assinaturas Digitais Baseadas em Hash

Ferramenta didática (disciplina de criptografia) para geração de chaves, assinatura digital e verificação utilizando esquemas de assinatura baseados em funções de hash: **Lamport OTS**, **W-OTS+** (Winternitz One-Time Signature Plus) e uma construção com **Árvore de Merkle**.

---

## 1. Visão Geral e Esquemas

O projeto implementa e compara três abordagens para assinaturas digitais:

1. **Lamport OTS (One-Time Signature)**: Esquema conceitual de assinatura de uso único baseado em SHA-256. Rápido, porém com assinaturas e chaves de tamanho grande (8 KB de dados criptográficos por assinatura). Demonstra de forma didática os riscos graves da reutilização de chaves de uso único.
2. **W-OTS+ (Winternitz One-Time Signature Plus)**: Variante otimizada que utiliza cadeias de iterações de hash e soma de verificação (*checksum*), reduzindo drasticamente o tamanho das chaves e das assinaturas através de um parâmetro de compromisso $w$ (ex.: $w=4$ ou $w=16$).
3. **Árvore de Merkle**: Estrutura em árvore binária que autentica múltiplas folhas W-OTS+ sob uma única chave pública global (a raiz da árvore). Permite que um mesmo par de chaves global realize múltiplas assinaturas (uma para cada folha/índice).

---

## 2. Pré-requisitos e Dependências

Para compilar e executar o projeto, você precisará de:

- **Compilador C++**: compatível com C++17.
- **CMake**
- **OpenSSL**: bibliotecas de desenvolvimento (`libcrypto`).

### Instalação das dependências

#### Ubuntu
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

---

## 3. Como Compilar o Projeto

O projeto utiliza o **CMake** como sistema de build. Recomenda-se compilar em um diretório separado (`build/`).

- 1. Configurar o build com CMake

A partir da raiz do repositório (`lamport_sig/`):

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
```

- 2. Compilar os binários

```bash
cmake --build build -j$(nproc)
```

Após a compilação, os seguintes artefatos estarão presentes no diretório `build/`:
- `liblamport_sig_crypto.a`: Biblioteca estática de infraestrutura criptográfica (SHA-256, separação de domínio e gerador de números aleatórios seguros).
- `test_hash`: Executável de testes unitários da infraestrutura criptográfica.
- `lamport_sig`: Executável da interface de linha de comando para Lamport, W-OTS+ e Merkle.
- `benchmark`: Comparação de tempos em memória e tamanhos dos formatos binários.

---

## 4. Como Executar os Testes

Após a compilação, você pode rodar os testes automatizados de duas maneiras:

```bash
ctest --test-dir build -V
```

---

## 6. Estrutura do Repositório

```text
lamport_sig/
├── CMakeLists.txt              # Configuração do build com CMake
├── README.md                   # Este arquivo (guia de compilação e uso)
├── include/                    # Headers públicos (.hpp)
│   ├── crypto/                 # SHA-256 e RNG seguro
│   ├── schemes/                # Implementação dos esquemas (Lamport, W-OTS+, Merkle)
│   ├── serialization/          # Formato e persistência de chaves e assinaturas
│   └── cli/                    # Interface de linha de comando
├── src/                        # Implementação dos módulos (.cpp)
│   ├── crypto/
│   ├── schemes/
│   ├── serialization/
│   └── cli/
├── tests/                      # Testes automatizados e vetores de teste
├── experiments/                # Scripts e programas de benchmark e avaliação
└── docs/                       # Documentação técnica e relatórios
```

## Documentação

- [Como funciona o Lamport OTS](docs/lamport.md)
- [Como funciona o W-OTS+](docs/wots.md)
- [Como funciona a árvore de Merkle](docs/merkle.md)
- [Comparação experimental](docs/experimentos.md)
