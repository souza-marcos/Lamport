# Lamport OTS

Lamport OTS (*one-time signature*) assina uma mensagem por par de chaves. Esta implementação usa SHA-256, cujo resultado tem 32 bytes. O código está em `include/schemes/lamport.hpp` e `src/schemes/lamport.cpp`.

## Ideia básica

Para cada um dos 256 bits do resumo da mensagem, a chave privada guarda dois segredos independentes: um para `0` e outro para `1`.

```text
Posição i       segredo para 0       segredo para 1
    i             s[i][0]              s[i][1]
```

A chave pública contém o hash de cada segredo. A assinatura revela um segredo por posição, escolhido pelo bit correspondente do resumo. A verificação calcula o hash dos segredos revelados e os compara com a chave pública.

Exemplo com as três primeiras posições. `0x11 × 32` representa 32 bytes iguais a `0x11`. Os valores públicos são `SHA-256(0x01 || segredo)`, abreviados a oito dígitos hexadecimais na tabela.

| Posição | Chave privada: segredo para `0` | Chave pública: hash para `0` | Chave privada: segredo para `1` | Chave pública: hash para `1` |
|---|---|---|---|---|
| `0` | `s[0][0] = 0x11 × 32` | `c2ad0a99…` | `s[0][1] = 0x22 × 32` | `5c1b9245…` |
| `1` | `s[1][0] = 0x33 × 32` | `40910b8c…` | `s[1][1] = 0x44 × 32` | `bac48a17…` |
| `2` | `s[2][0] = 0x55 × 32` | `7b3cdd9e…` | `s[2][1] = 0x66 × 32` | `7d7859b9…` |

Um resumo iniciado por `101` seleciona `s[0][1]`, `s[1][0]` e `s[2][1]`: `0x22 × 32`, `0x33 × 32` e `0x66 × 32`. Seus hashes correspondem às entradas públicas `5c1b9245…`, `40910b8c…` e `7d7859b9…`. A verificação usa os hashes completos e percorre as 256 posições. Os bytes repetidos são ilustrativos; `keygen` gera segredos aleatórios.

## Como esta implementação funciona

1. **Gerar chaves (`keygen`)**: o gerador seguro do OpenSSL cria 512 valores secretos de 32 bytes. A chave pública contém o hash de cada um deles.
2. **Assinar (`sign`)**: calcula-se o resumo da mensagem. Para cada posição `i`, a assinatura recebe `s[i][0]` ou `s[i][1]`, conforme o bit `i` do resumo. Depois, a chave privada é marcada como usada.
3. **Verificar (`verify`)**: calcula-se novamente o resumo da mensagem. Para cada posição, o hash do segredo apresentado deve coincidir com o elemento esperado da chave pública. Uma divergência rejeita a assinatura.

Os bits são lidos do mais significativo para o menos significativo em cada byte: o bit `0` é o bit mais à esquerda do primeiro byte do resumo.

### Separação de domínios

O primeiro byte distingue o hash da mensagem do hash de um segredo:

```text
Resumo da mensagem:  SHA-256(0x00 || mensagem)
Elemento público:    SHA-256(0x01 || segredo)
```

`||` indica concatenação de bytes. Assinatura e verificação seguem essas regras.

## Por que a chave é de uso único?

Cada assinatura revela um segredo por posição. Se a chave assinar duas mensagens com resumos diferentes, ambas as opções ficam expostas nas posições em que os bits diferem. Quem conhece os dois segredos de uma posição pode assinar tanto `0` quanto `1` nela. Por isso, `sign` lança `KeyAlreadyUsedError` quando a chave já foi usada.

O campo `PrivateKey::used` controla a assinatura em memória. Na CLI, o estado de consumo também é gravado no arquivo da chave privada antes de gravar a assinatura. Um arquivo de bloqueio (`private.key.lock`) impede que dois processos da ferramenta usem a mesma chave ao mesmo tempo. A chave atualizada é sincronizada e substitui a anterior antes de entregar a assinatura. Uma cópia antiga da chave privada ainda pode ser restaurada e reutilizada; não há como impedir isso apenas com um arquivo local.

Em `demo lamport-reuse`, a chave é copiada antes das duas assinaturas. Cada cópia conserva o estado de chave não usada.

## W-OTS+ e árvores de Merkle

### W-OTS+

W-OTS+ também assina uma única mensagem por chave. Em vez dos pares de segredos de Lamport, usa cadeias de hash: cada dígito do resumo seleciona um ponto de uma cadeia. Com `w=4`, os dígitos vão de `0` a `3`. Exemplo de uma cadeia:

```text
x0 -> x1 -> x2 -> x3
```

`x0` é secreto e `x3` faz parte da chave pública. Se o dígito for `2`, a assinatura revela `x2`; o verificador avança uma etapa e confere se chega a `x3`. Cada seta representa uma etapa que usa o endereço da cadeia e a semente pública.

Com `w=4`, o resumo SHA-256 ocupa 128 cadeias e o checksum ocupa mais 5. O checksum impede que uma assinatura seja alterada apenas avançando nas cadeias. A chave continua sendo de uso único. Detalhes em [W-OTS+](wots.md).

### Árvore de Merkle

A árvore de Merkle reúne várias chaves de uso único sob uma chave pública: a raiz. Neste projeto, cada folha é calculada a partir de uma chave pública W-OTS+. Uma árvore de altura `2` tem quatro folhas e permite quatro assinaturas:

```text
           raiz
         /      \
       N01      N23
      /   \    /   \
     L0   L1  L2   L3
```

`L0` a `L3` são hashes das chaves públicas W-OTS+; `N01` é o hash de `L0` com `L1`, e `N23` é o hash de `L2` com `L3`. Para assinar com a folha `L2`, a assinatura inclui a assinatura W-OTS+, o índice `2` e os hashes irmãos `L3` e `N01`. O verificador reconstrói `L2`, depois `N23` e a raiz, e compara essa raiz com a chave pública. A árvore poderia usar chaves Lamport nas folhas; a implementação usa W-OTS+. Detalhes em [Merkle](merkle.md).

## Tamanhos dos dados criptográficos

| Dado | Cálculo | Tamanho |
|---|---:|---:|
| Chave privada | 512 × 32 bytes | 16.384 bytes |
| Chave pública | 512 × 32 bytes | 16.384 bytes |
| Assinatura | 256 × 32 bytes | 8.192 bytes |

Esses valores não incluem os metadados dos arquivos. O formato atual adiciona 9 bytes à chave privada (identificador e estado) e 8 bytes à chave pública e à assinatura (identificador).

## Uso pela CLI

```bash
./build/lamport_sig keygen --scheme lamport --out keys/
./build/lamport_sig sign --scheme lamport --key keys/private.key --message message.txt --out signature.bin
./build/lamport_sig verify --scheme lamport --key keys/public.key --message message.txt --signature signature.bin
./build/lamport_sig demo lamport-reuse
```

`keygen` cria `private.key` e `public.key` sem sobrescrever arquivos existentes. A chave privada é criada com permissões restritas. `sign` consome a chave mesmo se a gravação posterior da assinatura falhar. `verify` retorna código `0` para assinatura válida, `1` para assinatura inválida e `2` para erros de uso ou arquivo.

Os arquivos usam um formato binário fixo com identificadores distintos para chave privada, chave pública e assinatura. O leitor rejeita identificadores errados e tamanhos inesperados.

## Testes

Após compilar o projeto, execute `ctest --test-dir build --output-on-failure`. O teste `lamport` cobre o algoritmo; `cli` cobre arquivos, verificação em outro processo, rejeição de reutilização e assinatura truncada.
