# Comparação experimental

O executável `benchmark` mede geração de chaves, assinatura e verificação **em memória**. Ele faz dez execuções de cada configuração com a mesma mensagem de oito bytes e imprime a média em milissegundos. Os tamanhos são os tamanhos exatos dos formatos binários atuais, calculados a partir do número de elementos; incluem identificadores e estado, quando presentes.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/benchmark > experiments/results.csv
```

## Execução de referência

Uma execução local em 7 de novembro de 2026, em AMD Ryzen 5 5500U, GCC 13.3 e OpenSSL 3.0.13, produziu:

| Esquema | Parâmetros | Chave privada | Chave pública | Assinatura | Geração | Assinatura | Verificação |
|---|---|---:|---:|---:|---:|---:|---:|
| Lamport | SHA-256 | 16.393 B | 16.392 B | 8.200 B | 0,430 ms | 0,002 ms | 0,130 ms |
| W-OTS+ | `w=4` | 4.298 B | 4.297 B | 4.265 B | 0,832 ms | 0,306 ms | 0,370 ms |
| W-OTS+ | `w=16` | 2.186 B | 2.185 B | 2.153 B | 1,794 ms | 0,771 ms | 0,947 ms |
| Merkle | `w=4`, `h=4` | 69.614 B | 42 B | 4.430 B | 16,961 ms | 0,378 ms | 0,482 ms |
| Merkle | `w=16`, `h=4` | 35.822 B | 42 B | 2.318 B | 31,610 ms | 0,887 ms | 1,097 ms |

Os valores mostram o compromisso esperado nesta implementação: `w=16` reduz os arquivos, mas usa cadeias mais longas; Merkle reduz a chave pública distribuída à raiz, ao custo de gerar todas as folhas e manter uma chave privada maior. Os tempos dependem da máquina, da carga do sistema e da versão das bibliotecas. Não incluem leitura, escrita, sincronização ou bloqueio de arquivos, e uma única execução com dez amostras não caracteriza a variabilidade estatística.
