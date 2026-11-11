# Lamport OTS

Lamport OTS (*one-time signature*) permite assinar **uma mensagem por par de chaves**. A implementação atual usa SHA-256: cada hash tem 32 bytes, ou 256 bits. As operações estão em `include/schemes/lamport.hpp` e `src/schemes/lamport.cpp`.

## Ideia básica

Para cada um dos 256 bits do resumo da mensagem, a chave privada guarda dois valores secretos independentes: um para o bit `0` e outro para o bit `1`.

```text
Posição i       segredo para 0       segredo para 1
    i             s[i][0]              s[i][1]
```

A chave pública guarda o hash de cada segredo. Ao assinar, revelamos apenas o segredo correspondente ao bit da mensagem naquela posição. Quem verifica calcula o hash dos segredos revelados e os compara com a chave pública.

## Como esta implementação funciona

1. **Gerar chaves (`keygen`)**: o gerador seguro do OpenSSL cria 512 valores secretos de 32 bytes. A chave pública contém o hash de cada um deles.
2. **Assinar (`sign`)**: calcula-se o resumo da mensagem. Para cada posição `i`, a assinatura recebe `s[i][0]` ou `s[i][1]`, conforme o bit `i` do resumo. Depois, a chave privada é marcada como usada.
3. **Verificar (`verify`)**: calcula-se novamente o resumo da mensagem. Para cada posição, o hash do segredo apresentado deve coincidir com o elemento esperado da chave pública. Uma divergência rejeita a assinatura.

Os bits são lidos do mais significativo para o menos significativo em cada byte: o bit `0` é o bit mais à esquerda do primeiro byte do resumo.

### Separação de domínios

O código adiciona um byte antes dos dados ao calcular os hashes. Assim, os dois usos de SHA-256 são distintos:

```text
Resumo da mensagem:  SHA-256(0x00 || mensagem)
Elemento público:    SHA-256(0x01 || segredo)
```

`||` significa concatenação de bytes. Tanto a assinatura quanto a verificação usam essas mesmas regras.

## Por que a chave é de uso único?

Cada assinatura revela um segredo por posição. Se a mesma chave assinar duas mensagens com resumos diferentes, nas posições em que os bits diferirem serão revelados **os dois segredos**. Isso fornece ao observador mais opções para montar uma assinatura indevida. Por isso, `sign` lança `KeyAlreadyUsedError` quando a chave já foi usada.

O campo `PrivateKey::used` controla a assinatura em memória. Na CLI, o estado de consumo também é gravado no arquivo da chave privada antes de gravar a assinatura. Um arquivo de bloqueio (`private.key.lock`) impede que dois processos da ferramenta usem a mesma chave ao mesmo tempo. A chave atualizada é sincronizada e substitui a anterior antes de entregar a assinatura. Uma cópia antiga da chave privada ainda pode ser restaurada e reutilizada; não há como impedir isso apenas com um arquivo local.

O auxiliar `detail::sign_raw` ignora esse controle e é usado apenas pela demonstração didática `demo lamport-reuse`. O fluxo normal usa `sign`.

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
