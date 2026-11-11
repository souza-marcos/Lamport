# Assinaturas digitais baseadas em hash

Projeto didático em C++17 para uma disciplina de criptografia. Implementa **Lamport OTS**, **W-OTS+** (`w=4` e `w=16`) e uma **árvore de Merkle com folhas W-OTS+** (alturas de 1 a 8). A árvore permite `2^h` assinaturas com uma chave pública global. Essa construção não implementa o XMSS completo.

## Compilação e testes

Requisitos: Linux, compilador C++17, CMake 3.16 ou superior, OpenSSL com headers de desenvolvimento e Bash. A persistência usa chamadas POSIX (`flock`, `fsync`, `rename`).

```bash
sudo apt install build-essential cmake libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

São seis testes: hash/aleatoriedade, Lamport, W-OTS+, Merkle, serialização e CLI. Eles verificam adulterações, reutilização, esgotamento, arquivos inválidos, mensagens vazias/binárias e concorrência na assinatura Merkle. As verificações dos testes também ficam ativas em Release.

## Uso

```bash
printf 'mensagem de exemplo' > message.txt
./build/lamport_sig keygen --scheme lamport --out keys/lamport
./build/lamport_sig sign --scheme lamport --key keys/lamport/private.key --message message.txt --out signature.bin
./build/lamport_sig verify --scheme lamport --key keys/lamport/public.key --message message.txt --signature signature.bin
./build/lamport_sig demo lamport-reuse

# Alternativas para a geração de chaves:
./build/lamport_sig keygen --scheme wots+ --w 16 --out keys/wots
./build/lamport_sig keygen --scheme merkle --w 4 --height 4 --out keys/merkle
```

Para assinar e verificar com as alternativas, use `--scheme wots+` ou `--scheme merkle` e os arquivos correspondentes. Em W-OTS+, `--w` é opcional nesses dois comandos; quando informado, precisa coincidir com o valor da chave.

Lamport e W-OTS+ permitem uma assinatura por chave. Merkle usa uma folha por assinatura: altura 4 permite 16 assinaturas. A ferramenta recusa sobrescrever arquivos existentes. `verify` retorna `0` para assinatura válida, `1` para inválida e `2` para erros de uso ou arquivo.

A CLI bloqueia a chave e persiste seu consumo antes de disponibilizar a assinatura. Uma interrupção pode consumir uma chave sem produzir assinatura. Restaurar uma cópia antiga da chave pode permitir sua reutilização. O projeto serve ao estudo dos algoritmos; não possui auditoria para uso em produção.

## Experimentos

```bash
./build/benchmark > experiments/results.csv
```

O CSV contém dez amostras por configuração, com os tamanhos dos arquivos e tempos dos algoritmos em memória. Merkle é comparado nas alturas 2, 4 e 6 para os dois valores de `w`. Consulte a [metodologia e os resultados](docs/experimentos.md).

## Organização e documentação

- `include/` e `src/`: hash e aleatoriedade, esquemas, serialização e CLI.
- `tests/`: testes dos algoritmos, formatos e comandos.
- `experiments/`: benchmark e amostras coletadas.
- [Estado do projeto, pendências, teoria e plano executado](plano_execucao_lamport_sig.md).
- Explicações de [Lamport](docs/lamport.md), [W-OTS+](docs/wots.md) e [Merkle](docs/merkle.md).
- [Formatos binários](docs/formatos_binarios.md).
- [Proposta original](PropostaCriptografiaMarcosDaniel.pdf).
