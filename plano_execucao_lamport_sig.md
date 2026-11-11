# Estado, fundamentos e plano de execução

Revisão em 11/11/2026, confrontando o código com `PropostaCriptografiaMarcosDaniel.pdf`.

## 1. O que já estava implementado

| Entrega da proposta | Evidência no projeto | Estado inicial |
|---|---|---|
| SHA-256 e aleatoriedade segura | `src/crypto/`, OpenSSL EVP e RAND_bytes | Implementado |
| Lamport OTS e controle de uso único | `src/schemes/lamport.cpp` | Implementado |
| W-OTS+ com w=4 e w=16 | `src/schemes/wots.cpp` | Implementado |
| Merkle com folhas W-OTS+ e índice persistente | `src/schemes/merkle.cpp` | Implementado; alturas de 1 a 8 |
| Geração, assinatura e verificação pela CLI | `src/cli/main.cpp` | Implementado nos três esquemas |
| Formatos binários e rejeição de arquivos malformados | `src/serialization/formats.cpp` | Implementado |
| Demonstração do risco de reutilizar Lamport | comando `demo lamport-reuse`, `docs/lamport.md` | Implementado; mostra segredos expostos, sem produzir uma falsificação completa |
| Testes automatizados | seis testes registrados no CMake | Passavam, mas os asserts de serialização eram desativados em Release |
| Comparação experimental | `experiments/benchmark.cpp` | Tamanhos e médias; Merkle somente com altura 4 |
| Repositório GitHub e histórico Git | metadados indisponíveis neste ambiente | Não verificável |

O núcleo proposto já existia. As lacunas locais eram a validade dos testes em Release, a comparação entre alturas diferentes, a documentação de entrega e trechos repetidos de infraestrutura.

## 2. Algoritmos e estruturas de dados

Notação: `H` é SHA-256, `n=32` bytes por hash, `d=256` bits por resumo, `m` é a mensagem, `L` é o número de cadeias W-OTS+, `h` é a altura e `N=2^h`. `||` indica concatenação. As complexidades abaixo descrevem esta implementação.

### SHA-256, domínios e aleatoriedade

Uma função hash mapeia uma entrada de tamanho variável para 256 bits. Resistência à pré-imagem dificulta descobrir um segredo a partir de seu hash; resistência à segunda pré-imagem e a colisões sustenta o uso de resumos e compromissos autenticados. Um hash isolado não identifica o autor de uma mensagem. SHA-256 é especificado pelo [NIST, FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

`Hash256 = std::array<uint8_t, 32>` representa o resultado fixo; `std::vector<uint8_t>` representa mensagens e arquivos. A função pública usa `EVP_Digest` do OpenSSL e verifica seu retorno. O custo de processar uma mensagem é O(|m|). A CLI carrega a mensagem inteira, usando O(|m|) de memória.

Lamport e Merkle prefixam um byte de domínio: mensagem `0x00`, segredo Lamport `0x01`, folha `0x02`, nó `0x03`. Isso distingue as entradas de cada finalidade. W-OTS+ utiliza sua própria codificação de domínio com 32 bytes, conforme a RFC, e calcula SHA-256 da mensagem sem esse prefixo de um byte.

Os segredos vêm de `RAND_bytes`, que deve produzir bytes imprevisíveis. Uma sequência fixa ou `std::mt19937` não substitui uma fonte criptográfica. [Documentação do OpenSSL EVP](https://docs.openssl.org/3.0/man3/EVP_DigestInit/).

### Lamport OTS

A chave privada contém dois segredos independentes `s[i][0]` e `s[i][1]` para cada bit; a pública contém seus hashes. Assinar revela `s[i][bit_i(H(0x00 || m))]`. Verificar aplica `H(0x01 || segredo)` e compara com o elemento público selecionado. Para revelar o outro bit sem conhecer seu segredo seria necessário inverter o hash. A construção original é descrita por [Lamport, 1979](https://lamport.azurewebsites.net/pubs/dig-sig.pdf).

A estrutura é `std::array<std::array<Hash256, 2>, 256>` para as chaves e `std::array<Hash256, 256>` para a assinatura. Acesso por posição custa O(1). Geração e verificação realizam O(d) hashes de tamanho fixo; assinatura seleciona O(d) elementos, além do hash O(|m|). Chaves têm `2dn` bytes e assinaturas `dn` bytes, antes dos cabeçalhos.

Duas mensagens com resumos diferentes expõem ambos os segredos nas posições divergentes. Isso amplia as combinações disponíveis ao adversário; não significa que duas assinaturas permitam assinar imediatamente qualquer mensagem. `bool used` impede o segundo uso pelo fluxo normal. `detail::sign_raw` existe para a demonstração explícita de reutilização.

### W-OTS+: cadeias e checksum

O resumo vira dígitos na base `w`. Cada segredo inicia uma cadeia com `w-1` passos; a chave pública guarda seu fim. Para um dígito `a_i`, a assinatura revela o ponto após `a_i` passos. A verificação executa os passos restantes. O checksum `C = soma(w-1-a_i)` dificulta alterar a mensagem apenas avançando nas cadeias. As fórmulas e funções de referência estão na [RFC 8391, seção 3.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1).

- `len1 = ceil(256 / log2(w))`.
- `len2 = floor(log_w(len1 × (w-1))) + 1`.
- `L = len1 + len2`: 133 para `w=4`, 67 para `w=16`.

Cada passo deriva chave e máscara de uma semente pública e de um endereço de 32 bytes que identifica cadeia, passo e finalidade. Usa `F(key, valor XOR máscara)`; F e PRF têm prefixos distintos. Os elementos ficam em `std::vector<Hash256>`, pois L depende de w. Um vetor de dígitos armazena mensagem e checksum.

Geração, assinatura e recuperação da chave pública custam O(Lw) no pior caso, além do hash da mensagem quando aplicável; memória e assinatura custam O(Ln). Aumentar w reduz o número de elementos, mas alonga as cadeias. A semente pública não é secreta. O estado `used` continua obrigatório. Os testes fixos desta revisão foram calculados separadamente em Python/hashlib; não são vetores oficiais de certificação.

### Árvore de Merkle e caminho de autenticação

Cada folha resume a chave pública W-OTS+ correspondente; cada nó resume os filhos em ordem. A raiz autentica todas as folhas. A assinatura apresenta a assinatura W-OTS+ e os h irmãos necessários para reconstruir a raiz. Isso aplica o princípio de autenticação por hashes, com separação entre folhas e nós; uma alteração deve mudar a raiz ou exigir uma quebra das propriedades do hash.

A implementação usa `std::vector<Hash256>` como árvore binária implícita: raiz em 1, filhos de i em `2i` e `2i+1`, folhas a partir de N. Não se trata de uma fila de prioridades. O irmão está em `i XOR 1`; o pai, em `i/2`. O caminho é outro vetor, com h hashes, percorrido da folha à raiz. A paridade do índice determina a ordem esquerda/direita.

A geração custa O(NLw + NL), incluindo as chaves W-OTS+ e a condensação de seus elementos. A chave privada guarda todas as folhas e nós: O(NLn + Nn) bytes. Assinar com a árvore em memória custa O(Lw+h), além de H(m), e verificar custa O(Lw+L+h), além de H(m). A assinatura ocupa O((L+h)n). A CLI também lê e regrava a chave privada completa; esse custo de arquivo cresce com N e não é medido pelo benchmark.

`uint32_t next_index` escolhe a próxima folha e avança após cada assinatura. Uma árvore permite N assinaturas. A construção é didática: não implementa o XMSS completo, suas L-trees, todos os endereços ou sua randomização de mensagens. Não se deve atribuir a ela automaticamente as provas de segurança do XMSS. [Detalhes locais](docs/merkle.md).

### Serialização, estado e concorrência

Arquivos são vetores de bytes com magic/versionamento, parâmetros, estado e elementos em ordem fixa. Inteiros de quatro bytes usam big endian. Os leitores conferem tamanho exato e cabeçalho antes de acessar os campos; isso evita interpretar truncamentos ou tipos incompatíveis. O formato não cifra a chave nem autentica o conteúdo do arquivo privado.

O bloqueio `flock` serializa assinaturas que usam o mesmo caminho de chave e respeitam o mesmo lock. `O_EXCL` reserva a saída sem sobrescrita. A chave consumida é gravada num temporário, sincronizada, substituída por `rename`, e o diretório é sincronizado antes de escrever a assinatura. O princípio é persistir o consumo antes de entregar o resultado: uma falha pode perder uma assinatura, mas o fluxo não libera de propósito uma chave já entregue. As regras completas estão em [formatos binários](docs/formatos_binarios.md).

Esse estado local não impede restauração de backups, cópias da chave ou acessos por caminhos com locks distintos. O uso seguro pressupõe um único arquivo canônico por chave. Controle contra rollback exigiria outra forma de armazenamento de estado, fora da proposta acadêmica.

## 3. Plano e execução local

| Ordem | Ação | Critério de conclusão | Resultado |
|---|---|---|---|
| 1 | Ler proposta, fontes e testes | Mapear todas as entregas e executar a versão recebida | Feito; seis testes passavam, com falha de cobertura em Release |
| 2 | Registrar o estado inicial no Git | Identificar branch e criar commit das mudanças prévias | Impedido: `.git` vazio e somente leitura |
| 3 | Criar branch separada | Criar `refactor/revisao-didatica` a partir da branch atual | Impedido pela ausência dos metadados Git |
| 4 | Limpar o projeto | Retirar artefatos regeneráveis e placeholders sem função | Feito; removidos `build/`, sete `.gitkeep` e `include/cli/`; atualizado `.gitignore` |
| 5 | Refatorar para leitura didática | Funções diretas, sem duplicação evitável e preservando os formatos | Feito; hash em uma chamada, gravação comum dos pares e leitura W-OTS+ reaproveitada |
| 6 | Corrigir e ampliar validação | Testes ativos em Release e referência independente para W-OTS+ | Feito; CHECK explícito, vetores fixos e mais casos de CLI |
| 7 | Completar experimentos | Comparar alturas e preservar amostras e tamanhos reais | Feito; 90 amostras, w=4/16, h=2/4/6, tamanhos via serialização |
| 8 | Consolidar documentação | Teoria, comandos reproduzíveis, resultados e pendências | Feito neste documento, README e relatório experimental |
| 9 | Validar entrega e fazer commit final | Compilar, executar testes e revisar alterações | Validação local feita; commit impedido pelo ambiente |

A refatoração mantém structs, arrays, vetores, laços e funções simples. Preserva o pequeno objeto que fecha arquivos ao sair do escopo, os bloqueios, as validações e a persistência: eles têm uma função concreta no projeto.

## 4. O que ainda falta

**Para concluir os pedidos de Git:** disponibilizar os metadados reais de `.git`, identificar a branch atual, registrar o estado inicial preservado, criar a branch separada e commitar as alterações desta revisão. Não foram criados commits nem branches fictícios. Uma cópia dos fontes recebidos está em `/tmp/sigtool-before-review/source.tar`, temporária e externa ao projeto; ela exclui build e diretórios de configuração/metadados.

Com o repositório real acessível, o fluxo planejado é:

1. Conferir `git status`, branch, histórico e diferenças em relação ao snapshot; preservar as mudanças prévias do usuário num commit na branch original.
2. Executar `git switch -c refactor/revisao-didatica` nessa base.
3. Aplicar as alterações revisadas, conferir o diff, executar os testes e fazer o commit `Refatora ferramenta didática e completa avaliação experimental`.
4. Verificar o remoto e a disponibilização no GitHub, entrega prevista pela proposta. Nenhum envio ao remoto foi executado nesta revisão.

**Implementação local da proposta:** nenhuma funcionalidade principal identificada ficou por implementar após esta revisão. Os seis testes e os experimentos são evidências funcionais, não uma auditoria ou prova completa de segurança. Ensaios com todas as alturas até 8, testes de queda de energia, proteção contra rollback, XMSS completo e validação por outra biblioteca seriam extensões futuras, não requisitos incluídos no plano executado.

## 5. Verificação

```bash
cmake -S . -B /tmp/sigtool-review-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/sigtool-review-build -j2
ctest --test-dir /tmp/sigtool-review-build --output-on-failure
/tmp/sigtool-review-build/benchmark > experiments/results.csv
```

Resultado: seis testes aprovados em Release e seis em Debug com UBSan (`-fsanitize=undefined -fno-sanitize-recover=all`), sem diagnóstico de comportamento indefinido; 90 amostras válidas em nove configurações. Uma cópia temporária do teste de serialização teve uma condição deliberadamente invertida: retornou código 1 mesmo com `-DNDEBUG`, confirmando que a correção acusa falhas em Release. Ambiente e medidas estão em [docs/experimentos.md](docs/experimentos.md). A validação incluiu os novos casos de mensagens vazias/binárias, preservação de chaves existentes e rejeição de w incompatível sem consumir a chave.
