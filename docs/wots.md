# W-OTS+

W-OTS+ é um esquema de assinatura de uso único com cadeias hash. Esta implementação oferece `w=4` e `w=16`, com elementos de 32 bytes. Ela segue as cadeias, endereços, máscaras, funções `F` e `PRF` e cálculo do checksum descritos na [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html). A RFC define um conjunto de parâmetros nomeado com `w=16`; `w=4` usa os mesmos algoritmos para a comparação proposta no projeto.

## Funcionamento

1. `keygen` cria um segredo independente para cada cadeia e uma semente pública. A chave pública contém o último elemento de cada cadeia.
2. `sign` calcula SHA-256 da mensagem, transforma o resumo em dígitos de base `w`, acrescenta o checksum e revela o ponto correspondente de cada cadeia. A chave é marcada como usada.
3. `verify` continua cada cadeia a partir do ponto revelado e compara o resultado com a chave pública.

Em cada passo, o endereço identifica a cadeia e a posição. `PRF` deriva uma chave e uma máscara da semente pública e desse endereço. A máscara é aplicada ao valor antes de `F`. Assim, passos distintos usam parâmetros distintos.

| Parâmetro | Dígitos da mensagem | Dígitos do checksum | Cadeias / elementos da assinatura | Dados da assinatura |
|---|---:|---:|---:|---:|
| `w=4` | 128 | 5 | 133 | 4.256 bytes |
| `w=16` | 64 | 3 | 67 | 2.144 bytes |

Os tamanhos da tabela excluem o identificador e o parâmetro do arquivo. A chave privada e a chave pública também guardam a semente de 32 bytes. A chave privada é de uso único; a CLI sincroniza e substitui o arquivo da chave privada com o estado consumido antes de gravar a assinatura.

## Uso

```bash
./build/lamport_sig keygen --scheme wots+ --w 4 --out keys/
./build/lamport_sig sign --scheme wots+ --key keys/private.key --message message.txt --out signature.bin
./build/lamport_sig verify --scheme wots+ --key keys/public.key --message message.txt --signature signature.bin
```

O parâmetro `--w` também pode ser informado em `sign` e `verify`; quando presente, deve corresponder ao valor gravado na chave. Uma cópia anterior da chave privada pode ser restaurada e reutilizada, portanto o arquivo deve ser protegido contra restaurações desse tipo.

O código está em `include/schemes/wots.hpp` e `src/schemes/wots.cpp`. O teste `wots` cobre os dois valores de `w`, assinatura válida, adulterações, parâmetro incompatível e reutilização.
