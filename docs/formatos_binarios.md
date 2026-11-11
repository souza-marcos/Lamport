# Formatos binários, versão 01

Os campos abaixo aparecem na ordem indicada, sem padding. `magic` é ASCII
com exatamente 8 bytes; `w`, `height` e `used` ocupam um byte cada.
`used` aceita 0 ou 1; `w` aceita 4 ou 16; `height` vai de 1 a 8.
Hashes e sementes têm 32 bytes. Os índices são inteiros de 4 bytes,
sem sinal, em big endian. Bytes extras e arquivos truncados são rejeitados.

Seja `L = 133` para `w = 4`, ou `L = 67` para `w = 16`, e `N = 2^height`.

| Magic | Campos após o magic | Tamanho em bytes |
|---|---|---|
| LAMPRV01 | used, 256 pares de segredos | 9 + 256 × 2 × 32 |
| LAMPUB01 | 256 pares de hashes públicos | 8 + 256 × 2 × 32 |
| LAMSIG01 | 256 segredos revelados | 8 + 256 × 32 |
| WOTPRV01 | w, used, pub_seed, L segredos | 42 + L × 32 |
| WOTPUB01 | w, pub_seed, L hashes públicos | 41 + L × 32 |
| WOTSIG01 | w, L elementos da assinatura | 9 + L × 32 |
| MERPRV01 | w, height, next_index, N folhas, 2N−1 nós | 14 + N × (32 + L × 32) + (2N−1) × 32 |
| MERPUB01 | w, height, root | 42 |
| MERSIG01 | w, height, leaf_index, pub_seed, L elementos W-OTS+, height irmãos | 46 + L × 32 + height × 32 |

Lamport armazena os pares por posição do bit, primeiro o elemento 0 e depois
o elemento 1. Os elementos W-OTS+ seguem a ordem das cadeias: dígitos da mensagem,
depois dígitos do checksum.

Cada folha privada Merkle contém `pub_seed` seguido dos `L` segredos W-OTS+.
O estado `used` é reconstruído por `índice da folha < next_index`;
`next_index = N` indica esgotamento. Os nós seguem os índices de heap de 1
até 2N−1: raiz primeiro; filhos de i em 2i e 2i+1. O nó 0 não é gravado.
A assinatura armazena os irmãos da folha até o nível imediatamente abaixo da raiz.

A CLI mantém o bloqueio exclusivo em `private.key.lock` durante leitura,
assinatura e persistência. Reserva a saída com `O_EXCL`, substitui a chave
por um temporário sincronizado, sincroniza o diretório e só então escreve e
sincroniza a assinatura. Se a persistência falhar, remove a saída; uma chave
já consumida não é revertida. Uma interrupção pode consumir uma chave sem
produzir assinatura, evitando sua reutilização.
