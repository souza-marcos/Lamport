# Árvore de Merkle com folhas W-OTS+

A árvore reúne várias chaves W-OTS+ de uso único sob uma única chave pública: a **raiz**. Uma árvore de altura `h` tem `2^h` folhas e permite até `2^h` assinaturas, cada uma com uma folha diferente. A CLI aceita alturas de 1 a 8.

## Construção e assinatura

`keygen` gera uma chave W-OTS+ independente por folha. Cada folha é o SHA-256 de um byte de domínio, seguido de `w`, da semente pública e dos elementos da chave pública W-OTS+. Cada nó interno é o SHA-256 de outro byte de domínio, seguido do filho esquerdo e do direito. A raiz é gravada na chave pública global.

`sign` escolhe a folha apontada por `next_index` e produz uma assinatura W-OTS+ dessa folha. A assinatura Merkle contém o índice, a semente pública W-OTS+, a assinatura W-OTS+ e um caminho de `h` hashes irmãos até a raiz. A CLI grava o próximo índice na chave privada antes de gravar a assinatura. Depois da última folha, recusa novas assinaturas.

`verify` reconstrói a chave pública W-OTS+ a partir da mensagem e da assinatura, calcula o hash da folha e percorre o caminho de autenticação. A ordem entre filho esquerdo e direito é determinada pelo índice. A assinatura é aceita somente se a raiz reconstruída for igual à chave pública global.

Esta é a construção Merkle definida para o projeto. **Não é uma implementação completa de XMSS**: em particular, a condensação da chave pública W-OTS+ é um hash de todos os elementos, e não a L-tree do XMSS.

## Uso

```bash
./build/lamport_sig keygen --scheme merkle --w 4 --height 4 --out keys/
./build/lamport_sig sign --scheme merkle --key keys/private.key --message message1.txt --out signature1.bin
./build/lamport_sig verify --scheme merkle --key keys/public.key --message message1.txt --signature signature1.bin
```

Repita `sign` com mensagens e nomes de arquivo diferentes até consumir as 16 folhas desse exemplo. Um arquivo de bloqueio (`private.key.lock`) impede que dois processos da ferramenta escolham a mesma folha ao mesmo tempo. A CLI grava a chave privada atualizada em um arquivo temporário, sincroniza esse arquivo, substitui o antigo por `rename` e sincroniza o diretório antes de gravar a assinatura. Uma interrupção pode desperdiçar uma folha, mas não libera novamente uma folha já entregue por essa sequência. Restaurar uma cópia antiga da chave privada ainda pode causar reutilização de folhas.

O código está em `include/schemes/merkle.hpp` e `src/schemes/merkle.cpp`. Os testes cobrem folhas em posições diferentes, mensagem, índice, caminho e assinatura adulterados, além do esgotamento das folhas.
