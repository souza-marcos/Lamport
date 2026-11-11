# Comparação experimental

## Método e reprodução

O benchmark executa dez vezes cada uma de nove configurações: Lamport; W-OTS+ com `w=4` e `w=16`; Merkle com ambos os valores de `w` e alturas `h=2`, `h=4` e `h=6`. Cada amostra gera uma chave nova e assina a mesma mensagem de oito bytes (`mensagem`). Todas as assinaturas são verificadas; uma falha encerra o programa com código 1.

Os tempos usam `std::chrono::steady_clock` e medem os algoritmos em memória. Os tamanhos são obtidos pelos próprios encoders, incluindo cabeçalhos, sementes e estado. A serialização e a impressão ficam fora dos intervalos medidos. Em Merkle, cada amostra mede a assinatura da primeira folha; não mede o consumo de todas as folhas.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
./build/benchmark > experiments/results.csv
```

O arquivo [results.csv](../experiments/results.csv) guarda as 90 amostras, com colunas `scheme,w,height,run,private_bytes,public_bytes,signature_bytes,keygen_ms,sign_ms,verify_ms`. `run` vai de 1 a 10 em cada configuração; `w=0` ou `height=0` indica parâmetro não aplicável. Cada linha representa uma execução, em vez da média usada na versão anterior do benchmark.

## Resultados de 11/11/2026

Ambiente: Linux x86_64, AMD Ryzen 5 5500U, GCC 13.3.0, CMake 3.28.3, OpenSSL 3.0.13, build Release. Tempos em milissegundos, expressos como **média ± desvio padrão amostral**; tamanhos em bytes. O desvio padrão não é um intervalo de confiança.

| Esquema | w | h | Privada (B) | Pública (B) | Assinatura (B) | Geração (ms) | Assinar (ms) | Verificar (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| lamport | — | — | 16393 | 16392 | 8200 | 0.423 ± 0.494 | 0.002 ± 0.000 | 0.132 ± 0.009 |
| wots+ | 4 | — | 4298 | 4297 | 4265 | 0.843 ± 0.034 | 0.301 ± 0.009 | 0.369 ± 0.021 |
| merkle | 4 | 2 | 17390 | 42 | 4366 | 3.284 ± 0.013 | 0.296 ± 0.005 | 0.374 ± 0.009 |
| merkle | 4 | 4 | 69614 | 42 | 4430 | 13.195 ± 0.093 | 0.295 ± 0.004 | 0.370 ± 0.010 |
| merkle | 4 | 6 | 278510 | 42 | 4494 | 53.206 ± 1.158 | 0.305 ± 0.022 | 0.388 ± 0.035 |
| wots+ | 16 | — | 2186 | 2185 | 2153 | 2.060 ± 0.277 | 0.869 ± 0.145 | 1.081 ± 0.196 |
| merkle | 16 | 2 | 8942 | 42 | 2254 | 7.953 ± 0.785 | 0.866 ± 0.158 | 1.068 ± 0.304 |
| merkle | 16 | 4 | 35822 | 42 | 2318 | 32.560 ± 1.181 | 0.829 ± 0.205 | 1.000 ± 0.172 |
| merkle | 16 | 6 | 143342 | 42 | 2382 | 111.774 ± 1.588 | 0.740 ± 0.012 | 0.908 ± 0.013 |

## Interpretação e limites

Nesta coleta, `w=16` reduz aproximadamente à metade a quantidade de elementos em relação a `w=4`, com maior custo das cadeias. A assinatura W-OTS+ ocupa 2.153 bytes com `w=16`, contra 8.200 bytes de Lamport, incluindo os metadados dos arquivos.

Merkle mantém a chave pública em 42 bytes. Aumentar h de 2 para 4, ou de 4 para 6, quadruplica o número de folhas: a geração e a chave privada crescem aproximadamente nessa proporção. A assinatura cresce somente 64 bytes a cada aumento de dois níveis, pois acrescenta dois hashes ao caminho. A altura permite comparar capacidade (4, 16 ou 64 assinaturas), custo de geração e armazenamento.

Os tempos não incluem leitura, escrita, bloqueios ou sincronização. A CLI lê e regrava a chave privada completa a cada assinatura; portanto, os tempos em memória não representam seu tempo total. Não há aquecimento separado, isolamento de CPU ou controle de frequência. A inicialização do OpenSSL pode afetar a primeira amostra; carga, escalonamento e frequência também explicam variações. Dez amostras numa única máquina sustentam uma comparação didática, sem caracterizar desempenho em todos os ambientes.

Para recalcular a tabela, agrupe por `(scheme,w,height)` e use `statistics.mean` e `statistics.stdev` nas três colunas de tempo. Os tamanhos devem ser constantes dentro de cada grupo. Os valores numéricos do CSV usam ponto como separador decimal.
