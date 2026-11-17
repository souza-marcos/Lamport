# Possíveis funcionalidades de segurança

Documento de propostas para o `sigtool`, elaborado em 11/11/2026 a partir do código atual. As funcionalidades abaixo **ainda não estão implementadas**, exceto os controles existentes explicitamente identificados. Os comandos apresentados são sugestões de interface, não comandos já disponíveis.

O objetivo é orientar uma evolução didática de Lamport OTS, W-OTS+ e Merkle. As prioridades consideram uma ferramenta local que armazena chaves em arquivos; não representam uma auditoria formal ou uma classificação de vulnerabilidades comprovadas.

## 1. Ponto de partida e ameaças consideradas

### Controles que já existem

| Controle | Onde aparece | O que oferece |
|---|---|---|
| SHA-256 pelo OpenSSL | `src/crypto/hash.cpp` | Cálculo dos resumos usados pelos esquemas |
| Aleatoriedade por `RAND_bytes` | `src/crypto/random.cpp` | Geração de segredos sem usar geradores comuns previsíveis |
| Separação de domínios e endereços | `src/schemes/` | Distinção entre usos do hash e passos das cadeias |
| Estado `used` ou `next_index` | `include/schemes/` | Recusa de reutilização pelo fluxo normal |
| Bloqueio por arquivo `.lock` | `src/cli/main.cpp` | Exclusão entre processos que respeitam o mesmo bloqueio |
| Persistência antes de entregar a assinatura | `replace_file` e `persist_signature`, na CLI | Evita liberar deliberadamente uma chave já consumida após falhas de gravação |
| Criação sem sobrescrita e chave com modo `0600` | `write_new`, na CLI | Proteção inicial contra sobrescrita e leitura por outros usuários |
| Cabeçalhos, tamanhos e parâmetros validados | `src/serialization/formats.cpp` | Rejeição de diversos arquivos malformados |
| Testes de adulteração, consumo e concorrência | `tests/` | Evidência funcional dos comportamentos testados |

### Cenários para as melhorias

1. Alguém obtém uma cópia do arquivo privado, mas não conhece uma eventual senha.
2. Um backup antigo da chave é restaurado e uma folha já utilizada volta a parecer disponível.
3. Outro processo manipula caminhos, arquivos ou diretórios acessíveis à ferramenta.
4. Um arquivo de entrada causa consumo excessivo de memória, demora ou erro de interpretação.
5. O verificador recebe uma chave pública substituída, uma assinatura reapresentada ou metadados enganosos.
6. O processo é interrompido durante uma atualização de estado.
7. O operador usa a ferramenta incorretamente, por exemplo copiando uma chave para assinar em duas máquinas.

O desenho inicial deve assumir um sistema operacional íntegro e uma conta de execução confiável. Um atacante com controle dessa conta enquanto a chave está desbloqueada, ou com privilégios administrativos, ultrapassa a proteção oferecida apenas por permissões e cifragem de arquivos. Serviços externos e hardware mudam esse modelo, mas exigem outro nível de projeto.

## 2. Visão geral das propostas

**P1:** primeira etapa de endurecimento da ferramenta. **P2:** expansão operacional após a base. **P3:** extensão avançada ou experimento comparativo. A prevenção de rollback é P1 pela relevância para OTS, mesmo tendo esforço alto.

Esforço relativo: **baixo** para mudanças locais; **médio** para integração entre módulos e formatos; **alto** para novos protocolos, infraestrutura ou validação extensa. Não são estimativas de prazo.

| ID | Funcionalidade | Prioridade | Esforço | Dependência principal |
|---|---|---|---|---|
| S01 | Diretórios privados e abertura segura de arquivos | P1 | Médio | Política de caminhos e permissões |
| S02 | Chave privada cifrada e autenticada por senha | P1 | Alto | Formato privado versionado e KDF |
| S03 | Prevenção de rollback e uso por cópias da chave | P1 | Alto | Autoridade de estado fora do backup local |
| S04 | Recuperação conservadora e testes de interrupção | P1 | Médio | Persistência atual |
| S05 | Limites de recursos e hash por blocos | P1 | Médio | Leitura de mensagens e API de hash |
| S06 | Identificação e confiança em chaves públicas | P1 | Médio | Serialização pública canônica |
| S07 | Contexto assinado e prevenção de replay | P2 | Alto | S06 e novo formato de assinatura |
| S08 | Auditoria de operações com integridade verificável | P2 | Médio/alto | Identidade da chave e política de registros |
| S09 | Inspeção, rotação e revogação de chaves | P2 | Médio/alto | S06; canal de confiança para revogação |
| S10 | Redução da exposição de segredos em memória | P2 | Médio | Revisão de buffers e cópias |
| S11 | API que dificulta copiar ou reusar chaves | P1 | Médio | Separar material secreto e estado de consumo |
| S12 | Fuzzing, testes independentes e validação contínua | P1 | Médio | CMake e testes existentes |
| S13 | Verificação estrita e migração explícita de formatos | P1 | Médio | Regras de compatibilidade documentadas |
| S14 | Isolamento do processo de assinatura | P3 | Alto | S01–S04 e implantação como serviço |
| S15 | Comparação com um esquema padronizado sem estado | P3 | Alto | Biblioteca e parâmetros adequados |

## 3. Propostas detalhadas

### S01 — Diretório privado e acesso seguro aos arquivos

**Risco tratado.** Uma chave criada com `0600` ainda pode ser manipulada por quem consegue substituir entradas de seu diretório. Caminhos com links simbólicos, arquivos especiais ou aliases também podem comprometer a política de bloqueio. Essas possibilidades dependem das permissões e do ambiente; não foi executada uma exploração nesta revisão.

**Situação atual.** A CLI usa `open`, `mkstemp`, `rename` e um lock derivado do caminho textual da chave. A criação de diretórios não impõe explicitamente `0700`, e `File` não aplica uma política geral de não seguir links.

**Implementação proposta.**

- Criar o armazenamento privado com `0700` e verificar proprietário e permissões ao abrir um diretório existente. Não alterar silenciosamente permissões de diretórios compartilhados fornecidos pelo usuário.
- Abrir primeiro um diretório confiável e operar sobre nomes relativos a seu descritor, com `openat`; no Linux, avaliar `openat2` com restrições de resolução.
- Rejeitar links e arquivos especiais na chave e no lock; usar `fstat` sobre o descritor efetivamente aberto. Evitar verificar um caminho e abri-lo depois como se nada pudesse mudar.
- Empregar `O_CLOEXEC`, conferir o modo efetivo dos arquivos privados e manter o lock no diretório confiável. Definir uma política para hard links e aliases.
- Evitar que a validação de arquivos especiais já cause bloqueio ao abrir um FIFO. A sequência de abertura precisa ser projetada para isso.

**Fundamento e estruturas.** A ameaça de TOCTOU ocorre quando o objeto muda entre verificação e uso. Descritores de diretórios e arquivos mantêm referências aos objetos abertos. `O_NOFOLLOW` isolado não valida todos os componentes anteriores de um caminho. As regras estão descritas no [manual de openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).

**Arquivos envolvidos.** `src/cli/main.cpp` e `tests/test_cli.sh`.

**Aceitação.** Testar chave/lock com link simbólico, diretório gravável por terceiros, permissões inadequadas, FIFO, hard links e troca concorrente de caminhos. Rejeitar entradas proibidas sem sobrescrever arquivos ou consumir uma folha.

**Limite.** Canonicalizar um caminho não coordena cópias independentes da chave. `flock` é um bloqueio cooperativo; seu comportamento também depende do sistema de arquivos. [Manual de flock](https://man7.org/linux/man-pages/man2/flock.2.html).

### S02 — Cifragem autenticada da chave privada

**Risco tratado.** Leitura de segredos e adulteração do arquivo privado por alguém que obteve acesso ao armazenamento.

**Situação atual.** Os formatos `LAMPRV01`, `WOTPRV01` e `MERPRV01` armazenam material secreto em claro. Validar magic e tamanho não autentica o conteúdo.

**Implementação proposta.** Criar um contêiner privado versionado com KDF, salt, parâmetros, nonce, ciphertext e tag. Derivar uma chave de cifragem da senha e usar AEAD, por exemplo AES-256-GCM pelo OpenSSL. Autenticar o cabeçalho como dados associados. Não usar SHA-256 da senha diretamente como chave.

Uma opção compatível com o OpenSSL 3.0 usado na revisão é [scrypt](https://docs.openssl.org/3.0/man7/EVP_KDF-SCRYPT/). Argon2id é outra opção, mas requer verificar a biblioteca/provedor disponível e os custos de integração; não se deve presumir sua disponibilidade no OpenSSL 3.0. A [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) descreve Argon2 e perfis de parâmetros.

A senha deve ser solicitada sem eco; automação pode receber um descritor dedicado. Evitar senha em argumento de processo, logs ou exemplos com segredo literal. A política deve definir salt aleatório, custos mínimos e máximos da KDF e unicidade de nonce por chave AEAD, inclusive nas regravações de estado. Não reutilizar um nonce fixo.

**Fundamento e estruturas.** Uma KDF onerosa dificulta tentativas de senha; AEAD combina confidencialidade e autenticação. Os metadados públicos do contêiner podem ser autenticados como AAD. Validar limites de tamanho e de custo antes da KDF, pois o cabeçalho ainda não está autenticado nesse momento. Só entregar plaintext à aplicação após confirmar a tag. [Interface AEAD, RFC 5116](https://www.rfc-editor.org/rfc/rfc5116.html); [API EVP](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/).

**Arquivos envolvidos.** `include/serialization/formats.hpp`, `src/serialization/formats.cpp`, CLI, testes e eventual módulo pequeno de proteção do contêiner.

**Aceitação.** Senha errada, tag alterada, cabeçalho adulterado, truncamento e parâmetros abusivos devem falhar sem assinar, modificar a chave ou deixar segredos em temporários. Testar nova cifragem a cada atualização e migração explícita de arquivos antigos.

**Limite.** AEAD não detecta a restauração de um arquivo antigo que continua autenticamente cifrado. Uma senha fraca continua sujeita a tentativa offline. Perder a senha pode tornar a chave irrecuperável.

### S03 — Prevenção de rollback e duplicação do estado

**Risco tratado.** Reutilizar a mesma chave Lamport/W-OTS+ ou a mesma folha Merkle ao restaurar um backup, copiar a chave ou assinar em máquinas diferentes.

**Situação atual.** `used` e `next_index` ficam no arquivo privado. O lock protege processos que usam o mesmo caminho, mas não cópias com locks diferentes.

**Implementação proposta.** Definir uma única autoridade de consumo por identificador de chave, fora do domínio que pode ser restaurado junto ao arquivo privado. Um serviço de assinatura centralizado ou um registro remoto autenticado pode reservar atomicamente cada índice antes de produzir uma assinatura. Hardware com estado monotônico é outra linha de estudo, sem presumir que qualquer TPM/HSM suporte o esquema e a transação necessários.

Um registro pode conter `key_id`, `next_index`, `state_version`, estado operacional e vínculo com os parâmetros da chave. Cada assinatura solicita uma reserva única e irreversível. Se houver falha depois da reserva, o índice é perdido. Se o serviço estiver indisponível, o modo protegido deve recusar assinar, sem retornar silenciosamente ao controle local.

**Fundamento e estruturas.** Exclusão mútua coordena acessos simultâneos; monotonicidade impede voltar ao estado anterior. São propriedades diferentes. Um banco transacional pode fazer a reserva atômica, mas restaurar o banco e a chave juntos desfaz a proteção. Um hash, HMAC ou contador dentro do mesmo backup também pode ser restaurado.

A gestão correta do estado é uma exigência central das assinaturas com estado discutidas na [RFC 8391, seção 9](https://www.rfc-editor.org/rfc/rfc8391.html#section-9). O registro externo aqui descrito é uma proposta arquitetural para o projeto, não um protocolo pronto definido pela RFC.

**Arquivos envolvidos.** Fluxo de assinatura na CLI, identificação de chaves e componente de estado. Manter a regra criptográfica de consumo explícita nos esquemas.

**Aceitação.** Restaurar uma chave antiga, usar duas cópias e disparar assinaturas concorrentes deve nunca reservar o mesmo índice. Testar timeout, repetição de requisição, reinício do serviço e recuperação após reserva sem assinatura.

**Limite.** Uma cópia dos segredos ainda permite assinar por outro programa. O registro protege o fluxo que exige sua autorização; impedir o uso fora dele exige custódia exclusiva dos segredos. Um registro externo precisa de autenticação, durabilidade, controle de acesso e uma política própria de recuperação. Em uma ferramenta totalmente offline, com todos os arquivos restauráveis, não há essa garantia apenas por software local.

### S04 — Recuperação conservadora e testes de falha

**Risco tratado.** Entregar assinatura sem consumo durável, repetir uma operação incerta ou apresentar sucesso com arquivo incompleto.

**Situação atual.** A ordem `persistir consumo → gravar assinatura` já existe e deve ser preservada. A ferramenta pode perder uma assinatura para evitar reutilização.

**Implementação proposta.** Adicionar pontos controlados de injeção de falha nos testes: antes/depois de sincronizar o temporário, substituir a chave, sincronizar o diretório e gravar a assinatura. Registrar separadamente o resultado operacional quando uma folha for consumida sem saída recuperável. Se a entrega exigir sobreviver a reinícios, incluir a política de sincronização do diretório da assinatura.

Um comando de inspeção pode detectar temporários órfãos, estado esgotado e inconsistências. Ele deve informar a situação sem restaurar uma versão antiga automaticamente. Caso seja necessário reenviar resultados, persistir a assinatura já produzida e vinculá-la ao identificador da requisição; reenviar os mesmos bytes não deve chamar `sign` novamente.

**Fundamento e estruturas.** Trata-se de uma máquina de estados com transições como `disponível → consumido → resultado persistido`. Um journal ou SQLite pode ajudar a recuperar operações, mas não torna automaticamente atômicos um banco e um arquivo externo. A [documentação de atomicidade do SQLite](https://www.sqlite.org/atomiccommit.html) mostra as hipóteses necessárias sobre armazenamento e sincronização.

**Arquivos envolvidos.** `replace_file`, `persist_signature`, CLI e testes de integração.

**Aceitação.** Interromper o processo em cada transição e reiniciar; uma assinatura entregue não pode permitir novo uso da folha. Simular escrita parcial, falta de espaço e erros de sincronização. Documentar que `kill -9` não equivale a uma queda de energia e não testa sozinho a durabilidade física.

### S05 — Limites de recursos e leitura por blocos

**Risco tratado.** Esgotamento de memória, CPU ou tempo por entradas grandes ou parâmetros hostis.

**Situação atual.** `read_message` aloca um vetor com o tamanho completo do arquivo. Chaves e assinaturas já têm limites estruturais, incluindo altura máxima 8.

**Implementação proposta.** Definir um limite documentado de mensagem e processar arquivos grandes em blocos com a API incremental EVP. Separar limites de mensagem, contêiner cifrado, caminho de autenticação e custo da KDF. Verificar limites antes de alocar ou converter tamanhos.

**Fundamento e estruturas.** Um buffer fixo, por exemplo de dezenas de KiB, permite calcular o hash com memória O(B), em vez de O(|m|). A assinatura precisa receber o resumo pelo caminho correto: Lamport calcula `SHA-256(0x00 || mensagem)`; W-OTS+ usa `SHA-256(mensagem)`. Não assinar `H(H(m))` por acidente ao adaptar a API. O modo antigo em memória e o modo por blocos devem gerar resultados equivalentes para a mesma chave de teste.

**Arquivos envolvidos.** `include/crypto/hash.hpp`, `src/crypto/hash.cpp`, leitura de mensagens e interfaces internas dos esquemas. A API que recebe um digest deve deixar explícito o domínio esperado, evitando confusão com mensagens comuns.

**Aceitação.** Testar limites exatos, arquivos vazios, bytes nulos, limites de blocos, crescimento do arquivo durante leitura e mensagens acima do limite. Decidir se alteração concorrente do arquivo é rejeitada ou se são assinados os bytes efetivamente lidos. Medir o pico de memória.

**Limite.** Hash por blocos reduz memória, não o tempo necessário para ler toda a mensagem. Se a ferramenta virar serviço, serão necessários quotas e controle de taxa adicionais.

### S06 — Impressão digital e confiança na chave pública

**Risco tratado.** Aceitar uma mensagem do atacante porque ele substituiu simultaneamente a assinatura e a chave pública.

**Situação atual.** `verify` verifica a relação matemática com a chave fornecida. Não existe um cadastro que relacione a chave a um proprietário confiável.

**Implementação proposta.** Adicionar `key-info` e uma impressão digital da chave pública. Definir uma codificação pública canônica, com esquema, parâmetros e versão, e calcular `key_id = SHA-256("sigtool:key-id:v1" || chave_publica_canonica)`. O identificador pode ser exibido em hexadecimal, sem expor segredos.

Permitir verificar contra uma impressão digital esperada, obtida por um canal confiável, ou contra um cadastro explícito de chaves autorizadas. Esse cadastro pode começar com um arquivo simples protegido por permissões; não precisa virar uma infraestrutura de certificados.

**Fundamento e estruturas.** Integridade da assinatura e confiança na origem da chave são problemas distintos. Um mapa `identificador → chave pública/política` representa a associação local. Vincular esquema e parâmetros ao identificador evita ambiguidades entre representações.

**Arquivos envolvidos.** Serialização pública, CLI e testes.

**Aceitação.** Uma assinatura válida com outra chave deve falhar quando a identidade esperada for diferente. Testar o mesmo identificador em execuções distintas e recusar mudanças silenciosas no cadastro.

**Limite.** A impressão digital recebida no mesmo canal comprometido da chave não cria confiança. Um campo chamado `nome_do_autor`, preenchido pelo assinante, também não comprova identidade.

### S07 — Envelope assinado com contexto e proteção contra replay

**Risco tratado.** Reaproveitar uma assinatura válida em outro contexto, destinatário, operação ou requisição.

**Situação atual.** Os esquemas assinam os bytes fornecidos. Uma assinatura válida pode ser apresentada várias vezes; isso não implica reutilização da chave privada.

**Implementação proposta.** Criar um formato de envelope com versão, `key_id`, finalidade, destinatário quando aplicável, identificador de requisição, nonce de desafio e digest do conteúdo. Todos os campos relevantes devem entrar nos bytes assinados. O receptor deve comparar finalidade/destinatário com valores esperados por ele e consumir atomicamente o desafio ou a requisição.

Datas de emissão e validade podem existir, mas dependem de relógio e política confiáveis. Não tratar a data escolhida pelo assinante como prova independente de tempo.

**Fundamento e estruturas.** Separação de contexto impede interpretar a mesma autorização em protocolos diferentes. Um conjunto ou tabela de desafios usados permite rejeitar repetições. Usar codificação determinística com campos de comprimento explícito; concatenar textos com separadores ambíguos pode produzir interpretações diferentes dos mesmos bytes.

**Arquivos envolvidos.** Novo formato de envelope, comandos de assinatura/verificação e testes. Versionar a alteração e manter o modo de assinatura de arquivo bruto explicitamente identificado.

**Aceitação.** Alterar finalidade, destinatário ou desafio deve invalidar a autorização. Repetir o mesmo desafio deve ser rejeitado de forma atômica pelo consumidor, mesmo com duas verificações concorrentes.

**Limite.** Um verificador offline sem memória não detecta todas as reapresentações. Para verificar arquivos estáticos, aceitar repetidamente a mesma assinatura pode ser o comportamento correto; proteção contra replay deve ser uma política do protocolo, não uma proibição universal.

### S08 — Registro de auditoria com integridade verificável

**Risco tratado.** Não conseguir explicar quais índices foram consumidos, quando houve falha e quais operações alteraram o estado.

**Situação atual.** A CLI imprime resultados, mas não mantém uma trilha de auditoria estruturada.

**Implementação proposta.** Registrar `event_id`, `key_id`, operação, índice, versão de estado e resultado. Distinguir reserva, consumo e entrega. Não registrar segredos, senha ou conteúdo completo da mensagem. Mesmo o digest de uma mensagem previsível pode revelar informação por tentativa de candidatos; registrá-lo exige uma decisão de privacidade.

Uma cadeia `h_i = H(h_(i-1) || evento_canonico_i)` permite conferir consistência. Para resistência à reescrita por um atacante, autenticar registros ou publicar checkpoints em um destino separado. Usar uma chave de auditoria independente e considerar que sua assinatura também pode ter limitações de uso único se for OTS.

**Fundamento e estruturas.** Uma lista encadeada por hashes evidencia alterações em relação a um checkpoint confiável. O atacante que controla o arquivo inteiro pode recalcular uma cadeia sem autenticação ou truncar seu final. Uma sequência crescente ajuda a ordenar eventos; relógios locais não bastam para estabelecer tempo confiável.

**Arquivos envolvidos.** CLI, persistência e eventual módulo pequeno de auditoria.

**Aceitação.** Detectar alteração, remoção e reordenação em relação ao checkpoint. Testar falha do destino de auditoria e definir se ela bloqueia a assinatura. A recuperação não deve devolver uma folha já consumida.

**Limite.** Logs locais não substituem S03. O destino externo cria novas necessidades de autenticação, disponibilidade e retenção.

### S09 — Inspeção, rotação e revogação

**Risco tratado.** Esgotar folhas sem planejamento, continuar confiando numa chave comprometida ou interpretar corrupção como chave utilizável.

**Implementação proposta.** Adicionar `key-info`, `key-check` e alertas de capacidade: esquema, parâmetros, identificador, estado e assinaturas restantes. Para Merkle, a capacidade é `2^h - next_index`. Uma checagem profunda opcional pode reconstruir chaves públicas e nós para detectar corrupção, com o custo claramente informado.

Permitir cadastrar uma chave substituta antes do esgotamento. Uma declaração de transição precisa de autenticação; se for assinada pela chave antiga, reservar capacidade para isso. Para revogação, definir uma autoridade confiável, versão da lista e política de atualização. Uma chave já comprometida não deve ser a única autoridade capaz de resolver sua própria revogação.

**Fundamento e estruturas.** Uma máquina de estados pode distinguir `ativa`, `esgotada`, `revogada` e `inválida`. Validade matemática da assinatura é diferente de aceitação pela política. Revogação não apaga assinaturas antigas, e decidir sua validade histórica exige regras adicionais.

**Arquivos envolvidos.** CLI, cadastro de confiança de S06 e testes de parâmetros/estado.

**Aceitação.** Consultar ou conferir a chave não deve consumir índices. Rejeitar `next_index > 2^h`, informar esgotamento e testar revogação com assinatura matematicamente válida. Não executar uma assinatura real apenas para fazer um diagnóstico.

**Limite.** Recalcular a estrutura detecta corrupção, não comprova que a chave nunca foi utilizada. Não deve existir comando que simplesmente zere `used` ou `next_index` para recuperar capacidade.

### S10 — Reduzir a permanência de segredos em memória

**Risco tratado.** Senhas, buffers privados ou cópias de chaves persistirem em memória após o uso e aparecerem em dumps.

**Situação atual.** Os segredos ficam em arrays e vetores comuns; a CLI também mantém o arquivo privado serializado em memória. Liberar esses objetos não garante apagar seus bytes.

**Implementação proposta.** Mapear todas as cópias e usar limpeza explícita apropriada, como `OPENSSL_cleanse`, nos buffers controlados. Reduzir o tempo de vida de senha, chave derivada, material privado e dados temporários. Avaliar bloqueio de páginas e exclusão de core dumps conforme o ambiente, verificando falhas dessas operações.

**Fundamento e estruturas.** Uma atribuição de zeros comum pode ser eliminada por otimização quando não tem efeito observável. Uma estrutura pequena com destrutor de limpeza pode organizar a propriedade dos buffers; deve abranger os buffers reais, não só uma cópia de fachada. Ver [limpeza de memória no OpenSSL](https://docs.openssl.org/3.0/man3/OPENSSL_malloc/) e [heap seguro](https://docs.openssl.org/3.0/man3/OPENSSL_secure_malloc/).

**Arquivos envolvidos.** Material privado dos esquemas, serialização, geração aleatória e leitura de senha de S02.

**Aceitação.** Revisar os caminhos normais e de exceção, testar os wrappers de limpeza em buffers conhecidos e verificar falhas da alocação protegida. Não acessar memória já liberada para tentar demonstrar apagamento.

**Limite.** Não há garantia de apagar todas as cópias feitas por bibliotecas, registradores, swap ou armazenamento físico. Apagar o arquivo com `unlink` também não garante remoção de SSDs, snapshots e backups.

### S11 — API que dificulta reutilização acidental

**Risco tratado.** Um programa cliente copia `PrivateKey` antes de assinar e usa cada cópia uma vez, ou acessa a rotina de demonstração que ignora o consumo.

**Situação atual.** As structs privadas são copiáveis e expõem estado e segredos. `detail::sign_raw` está declarado no header de Lamport para a demonstração. O controle em memória pode ser contornado por quem usa a biblioteca sem seguir o fluxo da CLI.

**Implementação proposta.** Tornar o estado operacional menos acessível, explicitar a propriedade da chave e restringir cópias acidentais. Um tipo somente movível pode ajudar, mas seu movimento precisa deixar a origem inválida; o movimento padrão de arrays de bytes pode conservar os segredos na origem. Tratar esses detalhes sem criar uma hierarquia genérica de classes.

Retirar `sign_raw` da API pública e manter seu uso restrito ao executável de demonstração ou a um alvo didático separado. Documentar que a API normal deve persistir consumo antes de liberar a assinatura. Se houver um serviço de estado, a assinatura precisa passar por ele.

**Fundamento e estruturas.** Encapsulamento e propriedade única reduzem usos incorretos em programas cooperativos. Não transformam um segredo copiável em um recurso fisicamente impossível de duplicar. Um teste de tipo pode verificar que `PrivateKey` não é copiável; isso é uma garantia de compilação, não de segurança contra um operador malicioso.

**Arquivos envolvidos.** `include/schemes/*.hpp`, implementações, demonstração, decodificação e testes que constroem chaves.

**Aceitação.** Cópias não autorizadas deixam de compilar, uso após movimento é rejeitado e a demonstração continua explícita. Confirmar que serialização/restauração não reintroduz silenciosamente uma chave consumida.

**Limite.** Encapsulamento não resolve backups, cópias em disco, leitura da memória ou uso dos segredos em outro programa. Deve complementar S03, não substituí-lo.

### S12 — Fuzzing, testes independentes e execução contínua

**Risco tratado.** Falhas de parsing, acesso inválido à memória e erros criptográficos que passam quando assinatura e verificação repetem o mesmo equívoco.

**Situação atual.** Há seis testes, casos negativos e vetores fixos W-OTS+ calculados separadamente. A revisão anterior executou Release e Debug com UBSan, mas isso não equivale a uma campanha contínua de fuzzing ou a validação completa por outra implementação.

**Implementação proposta.** Criar alvos de fuzzing para os decoders e, futuramente, para os contêineres/envelopes. Iniciar com arquivos válidos de todos os formatos e mutações de cabeçalhos, comprimentos e parâmetros. Executar com limites de tempo/memória e sanitizadores; guardar entradas que revelem falhas como regressões pequenas.

Ampliar referências independentes para dígitos, checksum, cadeias, folhas e caminhos. Para comparação com bibliotecas externas, alinhar previamente parâmetros e formatos: a construção Merkle didática não é XMSS completo. Incluir builds Release e Debug em integração contínua e testar o caminho de erro do gerador aleatório sem usar dados previsíveis como fallback.

**Fundamento e estruturas.** Fuzzing explora entradas que os exemplos manuais não antecipam. Testes diferenciais confrontam duas implementações independentes; testes de propriedades verificam invariantes, como a rejeição após adulterar a assinatura. [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) e [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) ajudam a encontrar classes diferentes de erros.

**Arquivos envolvidos.** `tests/`, CMake e configuração de CI, caso o repositório use uma plataforma para isso.

**Aceitação.** Nenhuma entrada de teste provoca corrupção de memória, travamento sem limite ou aceitação indevida conhecida. Exceções de formato esperado são resultados normais do parser e devem ser tratadas pelo harness. Falhas de biblioteca/memória não devem ser mascaradas indiscriminadamente.

**Limite.** Fuzzing sem erros não prova segurança. Registrar corpus, duração, configuração e classes cobertas, em vez de afirmar que o algoritmo foi certificado.

### S13 — Verificação estrita e migração explícita

**Risco tratado.** Aceitar formatos antigos involuntariamente, confundir algoritmos, tratar erro como sucesso ou importar uma chave com estado reinicializado.

**Situação atual.** Há magics separados por esquema/tipo, tamanhos exatos e verificação de parâmetros. A CLI distingue sucesso, assinatura inválida e erro de uso/arquivo.

**Implementação proposta.** Preservar esses comportamentos e acrescentar uma política de versões e esquemas aceitos. Verificação automatizada deve usar código de saída e resultado estruturado, sem depender da tradução do texto exibido. Um modo estrito pode exigir `key_id`, versão e contexto esperados.

Migração e importação de chaves devem preservar `used`/`next_index`, manter o identificador da chave e validar parâmetros. Recusar downgrade automático do contêiner cifrado para um arquivo em claro. Se existirem duas representações simultâneas da mesma chave, deixar explícito qual é a autoridade de estado; cifrar ou migrar não cria capacidade nova.

**Fundamento e estruturas.** Falhar de forma fechada significa rejeitar quando as condições necessárias não puderem ser confirmadas. Uma tabela pequena de combinações permitidas de versão/esquema/parâmetros basta. Não é necessário criar uma camada genérica de plugins para três esquemas.

**Arquivos envolvidos.** CLI, serialização, documentação dos formatos e testes de migração.

**Aceitação.** Versão desconhecida, parâmetro incompatível, assinatura truncada, metadados obrigatórios ausentes e erro de leitura nunca resultam em sucesso. Uma chave consumida continua consumida depois da migração. Rejeitar estado impossível sem corrigir valores silenciosamente.

**Limite.** Comparar hashes públicos em tempo constante não deve ser apresentado como a principal defesa que falta: o verificador já opera sobre dados públicos. Caso sejam introduzidos MACs ou tokens secretos, seguir as APIs de autenticação e comparação apropriadas para esse novo uso.

### S14 — Isolamento do assinador e autorização de operações

**Risco tratado.** A aplicação que pede uma assinatura também ter acesso irrestrito aos segredos e poder assinar qualquer conteúdo.

**Implementação proposta.** Como extensão, manter os segredos em um processo com conta dedicada e oferecer uma interface local autenticada, por exemplo um socket Unix com permissões restritas. Cada cliente recebe autorização por chave e finalidade. Definir limites de requisições e uma política para solicitações duplicadas antes de oferecer acesso pela rede.

O assinador deve ser o único detentor da chave e da autoridade de estado. Se vários processos de trabalho forem usados, precisam compartilhar a mesma reserva atômica de índices. Aplicar isolamento e permissões antes de adicionar uma interface HTTP.

**Fundamento e estruturas.** Menor privilégio reduz o conjunto de componentes capazes de extrair segredos. Uma tabela `cliente → chaves/finalidades autorizadas` representa a política. Autenticar um cliente não autoriza automaticamente todas as operações.

**Arquivos envolvidos.** Novo executável de serviço e cliente, além da integração com S01–S04. Essa mudança vai além da CLI atual e deve ficar em etapa própria.

**Aceitação.** Cliente sem autorização não assina, excesso de requisições não esgota recursos sem controle e pedidos repetidos não consomem folhas inadvertidamente. Testar reinício, timeouts e concorrência.

**Limite.** Um processo comprometido com autorização ampla ainda pode solicitar assinaturas prejudiciais. Custódia em hardware só pode ser prometida após verificar o suporte real do dispositivo e o tratamento de estado do esquema.

### S15 — Comparação com assinatura padronizada sem estado

**Risco tratado.** Dependência operacional de um estado local que não pode retroceder.

**Implementação proposta.** Manter os três esquemas didáticos e criar um experimento separado com SLH-DSA, usando uma implementação mantida, parâmetros padronizados e vetores oficiais. Comparar tamanho, latência, integração e modelo de operação.

**Fundamento.** O [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) especifica SLH-DSA, um esquema baseado em hash sem a mesma obrigação de manter o índice OTS entre assinaturas. Isso altera a construção criptográfica; remover `next_index` da árvore atual não produz um esquema sem estado seguro.

**Arquivos envolvidos.** Novo alvo experimental e adaptador de biblioteca, sem reescrever Lamport/W-OTS+/Merkle para aparentarem conformidade.

**Aceitação.** Executar vetores de referência, rejeitar adulterações e medir configurações identificadas pelo nome padronizado. Verificar disponibilidade e versão da biblioteca na etapa de implementação; não presumir suporte na instalação atual do OpenSSL 3.0.

**Limite.** É uma comparação acadêmica adicional, com novos custos e dependências. Não elimina a necessidade de proteger a chave, autenticar sua origem, validar entradas e controlar autorização.

## 4. Ordem sugerida de implementação

| Etapa | Entregas | Justificativa | Critério para avançar |
|---|---|---|---|
| 1 | S01, limites básicos de S05, S11 e regras de S13 | Reduzir erros locais sem alterar as primitivas | Testes de arquivos, recursos, estado e compatibilidade aprovados |
| 2 | S02 e S06 | Proteger o material privado e identificar a chave esperada | Contêiner autenticado e confiança explícita funcionando |
| 3 | S04 e S12, ampliados em todas as etapas | Validar recuperação, parsing e integração | Falhas injetadas não permitem reutilização; regressões automatizadas |
| 4 | S03 e política de backup/importação | Enfrentar o risco mais específico das assinaturas com estado | Cópias/restaurações não obtêm o mesmo índice pelo fluxo protegido |
| 5 | S07, S08 e S09 | Dar contexto, rastreabilidade e ciclo de vida às operações | Protocolo e política de confiança documentados e testados |
| 6 | S10, com revisão desde S02 | Reduzir exposição de segredos em todos os buffers envolvidos | Cópias e caminhos de exceção revisados |
| 7 | S14 ou S15 | Explorar serviço isolado ou esquema alternativo | Escopo e dependências definidos em projeto próprio |

Para um trabalho de graduação, uma seleção manejável é **S01 + S06 + limites de S05 + testes de S12**. Um segundo incremento pode acrescentar **S02**. Uma demonstração controlada de rollback, acompanhada do desenho de S03 e de suas hipóteses, tem valor didático mesmo quando um serviço externo confiável não cabe no prazo. Nesse caso, a limitação deve continuar declarada.

## 5. Como avaliar o ganho de segurança

| Proposta | Evidência útil | Evidência insuficiente |
|---|---|---|
| Cifragem da chave | Alteração de ciphertext/cabeçalho/tag é rejeitada antes do uso | O arquivo deixou de ser legível num editor de texto |
| Prevenção de rollback | Backup antigo e duas cópias não obtêm o mesmo índice pelo fluxo protegido | Existe um contador ou hash no próprio arquivo privado |
| Concorrência | Reservas exclusivas com aliases, múltiplos processos e reinício | Duas assinaturas sequenciais funcionam |
| Confiança na chave | Chave substituída falha contra identidade previamente confiável | Assinatura e chave pública vieram juntas e verificam |
| Proteção contra replay | Receptor consome o desafio e rejeita a reapresentação concorrente | A assinatura possui um timestamp escolhido pelo emissor |
| Auditoria | Alterações são detectadas contra checkpoint autenticado independente | O log contém hashes encadeados apenas localmente |
| Resistência a entradas hostis | Limites, fuzzing e casos de corrupção documentados | Todos os arquivos válidos de exemplo são aceitos |
| Recuperação | Injeção de falhas preserva consumo; hipóteses de durabilidade declaradas | Um único teste de encerramento abrupto passou |

## 6. Decisões que devem acompanhar qualquer implementação

Cada funcionalidade escolhida deve registrar: ameaça tratada, hipótese de confiança, formatos alterados, comportamento em caso de falha, impacto no estado de consumo e teste de aceitação. Isso evita que um novo controle enfraqueça a regra central de uso único.

Não introduzir recuperação que zere índices, fallback para aleatoriedade previsível, restauração automática de chave antiga ou reenvio que assine novamente uma operação incerta. Não reutilizar uma chave Lamport para cifragem, autenticação de logs ou outras finalidades.

As recomendações deste documento são extensões possíveis. Elas não alteram o estado das funcionalidades descritas no [plano atual](../plano_execucao_lamport_sig.md), nem tornam a construção didática equivalente a XMSS ou a uma implementação auditada. Os formatos existentes estão descritos em [formatos binários](formatos_binarios.md).
