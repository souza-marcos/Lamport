# W-OTS+

W-OTS+ é um esquema de assinatura de uso único com cadeias hash. Esta implementação oferece `w=4` e `w=16`, com elementos de 32 bytes. Ela segue as cadeias, endereços, máscaras, funções `F` e `PRF` e cálculo do checksum descritos na [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html). A RFC define um conjunto de parâmetros nomeado com `w=16`; `w=4` usa os mesmos algoritmos para a comparação proposta no projeto.

## Funcionamento

1. `keygen` cria um segredo independente para cada cadeia e uma semente pública. A chave pública contém o último elemento de cada cadeia.
2. `sign` calcula SHA-256 da mensagem, transforma o resumo em dígitos de base `w`, acrescenta o checksum e revela o ponto correspondente de cada cadeia. A chave é marcada como usada.
3. `verify` continua cada cadeia a partir do ponto revelado e compara o resultado com a chave pública.

Em cada passo, o endereço identifica a cadeia e a posição. `PRF` deriva uma chave e uma máscara da semente pública e desse endereço. A máscara é aplicada ao valor antes de `F`. Assim, passos distintos usam parâmetros distintos.

### Exemplo de uma cadeia

Com `w=4`, cada dígito do resumo vale de `0` a `3`. Para a cadeia de índice `0`, use o segredo inicial `x0 = 0x11 × 32` e a semente pública `0x22 × 32`. A notação indica 32 bytes iguais a `0x11` ou a `0x22`. Aplicando os passos da implementação, a cadeia fica assim (hashes abreviados a oito dígitos):

| Posição | Valor |
|---|---|
| `x0` — segredo | `0x11 × 32` |
| `x1` | `08e75077…` |
| `x2` | `303a48c7…` |
| `x3` — elemento público | `21170315…` |

Se o dígito da mensagem nessa posição for `2`, `sign` inclui `x2` na assinatura. `verify` executa o passo restante e confere se o resultado é `x3`. Os outros dígitos seguem suas próprias cadeias; o checksum acrescenta cadeias que impedem alterar a assinatura apenas avançando os valores revelados. A comparação usa os 32 bytes completos. Os valores repetidos acima servem só para o exemplo; `keygen` sorteia os segredos e a semente.

| Parâmetro | Dígitos da mensagem | Dígitos do checksum | Cadeias / elementos da assinatura | Dados da assinatura |
|---|---:|---:|---:|---:|
| `w=4` | 128 | 5 | 133 | 4.256 bytes |
| `w=16` | 64 | 3 | 67 | 2.144 bytes |

Os tamanhos da tabela excluem o identificador e o parâmetro do arquivo. A chave privada e a chave pública também guardam a semente de 32 bytes. A chave privada é de uso único; a CLI sincroniza e substitui o arquivo da chave privada com o estado consumido antes de gravar a assinatura.

## Em relação ao Lamport

Lamport guarda dois segredos para cada um dos 256 bits do resumo: 512 segredos e uma assinatura de 8.192 bytes. W-OTS+ usa 133 cadeias com `w=4` ou 67 com `w=16`; as assinaturas ocupam 4.256 ou 2.144 bytes. As chaves privada e pública também são menores: 4.288 bytes com `w=4` ou 2.176 bytes com `w=16`, incluindo a semente, contra 16.384 bytes em Lamport. A redução de tamanho custa mais cálculos de hash, pois gerar e verificar uma assinatura exige percorrer trechos das cadeias. Ambos os esquemas continuam limitados a uma mensagem por chave. Veja o [exemplo de Lamport](lamport.md).

## Uso

```bash
./build/lamport_sig keygen --scheme wots+ --w 4 --out keys/
./build/lamport_sig sign --scheme wots+ --key keys/private.key --message message.txt --out signature.bin
./build/lamport_sig verify --scheme wots+ --key keys/public.key --message message.txt --signature signature.bin
```

O parâmetro `--w` também pode ser informado em `sign` e `verify`; quando presente, deve corresponder ao valor gravado na chave. Uma cópia anterior da chave privada pode ser restaurada e reutilizada, portanto o arquivo deve ser protegido contra restaurações desse tipo.

O código está em `include/schemes/wots.hpp` e `src/schemes/wots.cpp`. O teste `wots` cobre os dois valores de `w`, assinatura válida, adulterações, parâmetro incompatível e reutilização.
