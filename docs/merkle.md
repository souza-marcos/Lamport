# Árvore de Merkle com folhas W-OTS+

A árvore reúne várias chaves W-OTS+ de uso único sob uma única chave pública: a **raiz**. Uma árvore de altura `h` tem `2^h` folhas e permite até `2^h` assinaturas, cada uma com uma folha diferente. A CLI aceita alturas de 1 a 8.

## Construção e assinatura

`keygen` gera uma chave W-OTS+ independente por folha. Cada folha é o SHA-256 de um byte de domínio, seguido de `w`, da semente pública e dos elementos da chave pública W-OTS+. Cada nó interno é o SHA-256 de outro byte de domínio, seguido do filho esquerdo e do direito. A raiz é gravada na chave pública global.

`sign` escolhe a folha apontada por `next_index` e produz uma assinatura W-OTS+ dessa folha. A assinatura Merkle contém o índice, a semente pública W-OTS+, a assinatura W-OTS+ e um caminho de `h` hashes irmãos até a raiz. A CLI grava o próximo índice na chave privada antes de gravar a assinatura. Depois da última folha, recusa novas assinaturas.

`verify` reconstrói a chave pública W-OTS+ a partir da mensagem e da assinatura, calcula o hash da folha e percorre o caminho de autenticação. A ordem entre filho esquerdo e direito é determinada pelo índice. A assinatura é aceita somente se a raiz reconstruída for igual à chave pública global.

### Exemplo com quatro folhas

Com altura `h=2`, a árvore tem quatro folhas (`L0` a `L3`). Para mostrar o cálculo dos nós, tome como hashes das folhas os valores `L0 = 0x11 × 32`, `L1 = 0x22 × 32`, `L2 = 0x33 × 32` e `L3 = 0x44 × 32`. Cada expressão representa 32 bytes repetidos. Na chave real, esses valores vêm das chaves públicas W-OTS+.

Para nós internos, `H(a, b) = SHA-256(0x03 || a || b)`, onde `||` é concatenação. Os resultados abaixo mostram só os oito primeiros dígitos; cada hash completo tem 32 bytes.

| Nó | Cálculo | Início do hash |
|---|---|---|
| `N01` | `H(L0, L1)` | `378e7d54…` |
| `N23` | `H(L2, L3)` | `a48926ac…` |
| raiz | `H(N01, N23)` | `9e85da19…` |

Depois de usar `L0` e `L1`, `next_index` vale `2`. `sign` usa a terceira chave W-OTS+ e grava o índice `2`, a assinatura W-OTS+, sua semente pública e o caminho `[L3, N01]`. A partir da mensagem e da assinatura, `verify` reconstrói `L2`, calcula `H(L2, L3) = N23` e depois `H(N01, N23) = raiz`. A assinatura é válida se a raiz calculada coincidir com a chave pública.

Esta é a construção Merkle definida para o projeto. **Não é uma implementação completa de XMSS**: em particular, a condensação da chave pública W-OTS+ é um hash de todos os elementos, e não a L-tree do XMSS.

## Em relação ao W-OTS+ isolado

Uma chave W-OTS+ assina uma mensagem. A árvore de altura `h` reúne `2^h` chaves W-OTS+ independentes e permite assinar até `2^h` mensagens com a mesma raiz pública. No exemplo acima, são quatro assinaturas; com `h=4`, são 16. Cada assinatura carrega também um caminho de `h` hashes, e a chave privada precisa guardar qual folha será usada a seguir (`next_index`).

## Uso

```bash
./build/lamport_sig keygen --scheme merkle --w 4 --height 4 --out keys/
./build/lamport_sig sign --scheme merkle --key keys/private.key --message message1.txt --out signature1.bin
./build/lamport_sig verify --scheme merkle --key keys/public.key --message message1.txt --signature signature1.bin
```

Repita `sign` com mensagens e nomes de arquivo diferentes até consumir as 16 folhas desse exemplo. Um arquivo de bloqueio (`private.key.lock`) impede que dois processos da ferramenta escolham a mesma folha ao mesmo tempo. A CLI grava a chave privada atualizada em um arquivo temporário, sincroniza esse arquivo, substitui o antigo por `rename` e sincroniza o diretório antes de gravar a assinatura. Uma interrupção pode desperdiçar uma folha, mas não libera novamente uma folha já entregue por essa sequência. Restaurar uma cópia antiga da chave privada ainda pode causar reutilização de folhas.

O código está em `include/schemes/merkle.hpp` e `src/schemes/merkle.cpp`. Os testes cobrem folhas em posições diferentes, mensagem, índice, caminho e assinatura adulterados, além do esgotamento das folhas.
