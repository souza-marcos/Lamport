# Plano de execução — Ferramenta de assinaturas digitais Lamport, W-OTS+ e Árvore de Merkle

## 1. Visão geral do projeto

A proposta consiste em desenvolver uma ferramenta em C++ capaz de gerar chaves, assinar mensagens e verificar assinaturas utilizando três construções criptográficas: **Lamport OTS**, **W-OTS+** e uma construção baseada em **árvore de Merkle**, na qual cada folha representa uma chave pública W-OTS+ de uso único.

A ideia central é construir a ferramenta progressivamente. Primeiro, implementar e validar um esquema de assinatura simples. Depois, implementar uma alternativa mais eficiente em tamanho de assinatura. Por último, combinar várias chaves de uso único em uma única estrutura autenticada, permitindo assinar diferentes mensagens sem precisar distribuir uma chave pública independente para cada assinatura.

Essa sequência acompanha o objetivo da proposta: explorar as diferenças de eficiência entre Lamport e W-OTS+, e utilizar uma árvore de Merkle para autenticar múltiplas chaves públicas por meio de uma única chave pública global. Os experimentos devem comparar tamanhos de chaves e tempos de geração, assinatura e verificação.

### 1.1. História principal de utilização

Imagine que um usuário deseja assinar digitalmente uma mensagem e, posteriormente, permitir que outra pessoa verifique sua autenticidade.

Ao utilizar a ferramenta, o fluxo esperado será:

1. O usuário gera um par de chaves para o esquema escolhido.
2. O usuário utiliza a chave privada para assinar uma mensagem.
3. A ferramenta produz uma assinatura que pode ser armazenada ou enviada junto à mensagem.
4. Outra pessoa recebe a mensagem, a assinatura e a chave pública.
5. A ferramenta verifica se a assinatura corresponde à mensagem e à chave pública.
6. No caso da construção com Merkle, o usuário pode realizar várias assinaturas com um único par de chaves global, desde que utilize uma folha diferente da árvore para cada operação.

O projeto deverá entregar uma interface de linha de comando para geração de chaves, assinatura e verificação, além de testes automatizados e documentação dos problemas decorrentes da reutilização de chaves Lamport.

---

## 2. Etapa inicial — Definição da arquitetura e do comportamento da ferramenta

Antes de implementar qualquer algoritmo, é necessário decidir como os diferentes componentes irão se comunicar. Isso evita que cada algoritmo tenha uma interface diferente e que seja necessário reescrever funcionalidades posteriormente para integrá-los à ferramenta.

### 2.1. Definição da interface de utilização

A ferramenta terá um executável único, por exemplo, `lamport_sig`, que receberá comandos pelo terminal.

Uma possível interface seria:

```bash
# Gerar um par de chaves Lamport
./lamport_sig keygen --scheme lamport --out keys/

# Assinar uma mensagem
./lamport_sig sign --scheme lamport \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin

# Verificar uma assinatura
./lamport_sig verify --scheme lamport \
    --key keys/public.key \
    --message message.txt \
    --signature signature.bin
```

O mesmo fluxo deverá funcionar para W-OTS+:

```bash
./lamport_sig keygen --scheme wots+ --w 4 --out keys/

./lamport_sig sign --scheme wots+ \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin
```

E para a construção com Merkle:

```bash
./lamport_sig keygen --scheme merkle --w 4 --height 4 --out keys/

./lamport_sig sign --scheme merkle \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin
```

Nesse último caso, cada assinatura consumirá uma folha da árvore. Portanto, a ferramenta precisará controlar quantas assinaturas já foram realizadas e qual índice deverá ser utilizado na próxima operação.

A interface é apenas uma sugestão inicial, mas estabelecer esse comportamento desde o começo permite definir claramente os contratos de cada componente.

### 2.2. Organização interna do código

A implementação será dividida em módulos, evitando misturar operações criptográficas, manipulação de arquivos e interface de linha de comando.

Uma possível organização:

```text
lamport_sig/
├── CMakeLists.txt
├── README.md
│
├── include/
│   ├── crypto/
│   │   ├── hash.hpp
│   │   └── random.hpp
│   │
│   ├── schemes/
│   │   ├── lamport.hpp
│   │   ├── wots.hpp
│   │   └── merkle.hpp
│   │
│   ├── serialization/
│   │   └── file.hpp
│   │
│   └── cli/
│       └── commands.hpp
│
├── src/
│   ├── crypto/
│   ├── schemes/
│   ├── serialization/
│   ├── cli/
│   └── main.cpp
│
├── tests/
│   ├── test_hash.cpp
│   ├── test_lamport.cpp
│   ├── test_wots.cpp
│   └── test_merkle.cpp
│
└── experiments/
    └── benchmark.cpp
```

Os módulos terão responsabilidades bem delimitadas:

| Módulo | Responsabilidade |
|---|---|
| `crypto` | SHA-256 e geração de valores aleatórios criptograficamente seguros. |
| `lamport` | Geração de chaves, assinatura e verificação Lamport. |
| `wots` | Implementação das cadeias hash, cálculo do checksum e operações W-OTS+. |
| `merkle` | Construção da árvore, geração da chave global e caminhos de autenticação. |
| `serialization` | Leitura e escrita de chaves, mensagens e assinaturas. |
| `cli` | Interpretação dos comandos e comunicação com os módulos. |
| `tests` | Verificação automática do funcionamento e das propriedades esperadas. |
| `experiments` | Execução dos experimentos e coleta de métricas. |

Uma decisão importante é definir desde o início uma representação comum para hashes, parâmetros e mensagens. Por exemplo, um hash SHA-256 será representado por uma sequência de 32 bytes.

---

## 3. Etapa de implementação I — Infraestrutura criptográfica

A primeira funcionalidade real da ferramenta será a implementação dos componentes criptográficos utilizados pelos três esquemas.

Embora pareça uma etapa simples, ela é fundamental: tanto Lamport quanto W-OTS+ e Merkle dependem diretamente da segurança e da consistência dessas operações.

### 3.1. Implementação do SHA-256

O sistema precisará calcular o hash de mensagens, elementos das chaves e nós da árvore.

Será criada uma interface independente da implementação utilizada:

```cpp
using Hash256 = std::array<uint8_t, 32>;

Hash256 sha256(const std::vector<uint8_t>& data);
```

A implementação poderá utilizar uma biblioteca criptográfica consolidada, como OpenSSL, em vez de implementar SHA-256 manualmente. Isso reduz o risco de introduzir erros em um componente que não é o foco principal do trabalho.

Também será importante estabelecer uma convenção para separar os diferentes usos da função hash. Por exemplo, utilizar identificadores de domínio distintos para folhas e nós internos da árvore. Isso evita que entradas destinadas a operações diferentes sejam interpretadas como pertencentes ao mesmo contexto.

### 3.2. Implementação da geração segura de números aleatórios

A geração de chaves dependerá de valores aleatórios imprevisíveis.

Será implementada uma função que receba a quantidade de bytes desejada e retorne uma sequência de bytes gerada por uma fonte criptograficamente segura.

```cpp
std::vector<uint8_t> secure_random(size_t size);
```

Uma alternativa é utilizar `RAND_bytes`, disponibilizada pelo OpenSSL.

Não se deve utilizar um gerador convencional como `std::mt19937` para produzir material secreto. O objetivo aqui não é gerar números estatisticamente variados, mas valores que não sejam previsíveis por um possível atacante.

### 3.3. Testes da infraestrutura

Antes de implementar os esquemas, serão realizados testes específicos:

- Verificar o SHA-256 utilizando vetores de teste conhecidos.
- Verificar se a função produz exatamente 32 bytes.
- Verificar o comportamento com entradas vazias e mensagens de tamanhos diferentes.
- Verificar se a geração aleatória retorna a quantidade de bytes solicitada.
- Verificar se erros nas operações criptográficas são tratados corretamente.

**Critério para avançar:** os componentes de hash e aleatoriedade devem estar funcionando e possuir testes automatizados. Os demais módulos não deverão implementar suas próprias versões dessas funcionalidades.

---

## 4. Etapa de implementação II — Assinatura Lamport OTS

Com a infraestrutura pronta, será implementado o primeiro esquema de assinatura.

O Lamport OTS será a primeira funcionalidade completa da ferramenta, pois apresenta um fluxo relativamente direto e permitirá validar toda a estrutura de geração de chaves, assinatura e verificação.

### 4.1. História da funcionalidade: geração de chaves

Imagine que um usuário execute:

```bash
./lamport_sig keygen --scheme lamport --out keys/
```

A ferramenta deverá gerar um par de chaves.

Considerando SHA-256, cada elemento secreto e cada hash possuirá 256 bits, ou seja, 32 bytes.

Para cada posição do digest, serão gerados dois valores secretos independentes:

\[
SK = \{s_{i,0},s_{i,1}\}_{i=0}^{255}
\]

A chave pública será construída calculando o hash de cada elemento secreto:

\[
PK = \{H(s_{i,0}),H(s_{i,1})\}_{i=0}^{255}
\]

Portanto, a operação de geração deverá:

1. Criar 256 pares de valores secretos.
2. Calcular o hash de cada um dos 512 valores.
3. Organizar os resultados na estrutura de chave privada e pública.
4. Serializar as duas estruturas em arquivos.

Ao final, teremos:

```text
keys/
├── private.key
└── public.key
```

A chave privada conterá os valores aleatórios originais. A chave pública conterá seus respectivos hashes.

### 4.2. História da funcionalidade: assinatura de uma mensagem

Agora o usuário deseja assinar um arquivo:

```bash
./lamport_sig sign --scheme lamport \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin
```

A ferramenta deverá:

1. Ler o conteúdo da mensagem.
2. Calcular seu hash SHA-256.
3. Interpretar o resultado como uma sequência de 256 bits.
4. Para cada bit, selecionar o elemento secreto correspondente.
5. Montar a assinatura contendo os 256 valores selecionados.

Se o bit de uma determinada posição for zero, será revelado o elemento `s_{i,0}`. Se for um, será revelado `s_{i,1}`.

Assim:

\[
\sigma = \{s_{i,m_i}\}_{i=0}^{255}
\]

Onde `m_i` representa o i-ésimo bit do hash da mensagem.

O arquivo de assinatura conterá os elementos secretos selecionados, e não o conteúdo original da chave privada.

**Regra de segurança:** uma chave Lamport deve ser utilizada para assinar apenas uma mensagem. A ferramenta deverá controlar esse consumo para evitar reutilizações acidentais.

### 4.3. História da funcionalidade: verificação da assinatura

O destinatário recebe a mensagem, a assinatura e a chave pública.

A operação será:

```bash
./lamport_sig verify --scheme lamport \
    --key keys/public.key \
    --message message.txt \
    --signature signature.bin
```

A ferramenta deverá:

1. Calcular novamente o hash da mensagem recebida.
2. Interpretar o digest como uma sequência de bits.
3. Percorrer os elementos presentes na assinatura.
4. Calcular o hash de cada elemento revelado.
5. Comparar o resultado com o elemento correspondente da chave pública.

Se todas as comparações forem válidas, a assinatura será aceita.

Caso contrário, será rejeitada.

Essa etapa deverá validar não somente mensagens incorretas, mas também assinaturas truncadas, elementos modificados e chaves públicas incompatíveis.

### 4.4. Funcionalidade adicional: demonstração da reutilização de chaves

Após implementar o fluxo normal, será criada uma demonstração específica da falha provocada pela reutilização de uma chave Lamport.

O objetivo é permitir que alguém execute uma operação didática e observe o problema na prática.

Por exemplo:

```bash
./lamport_sig demo lamport-reuse
```

A demonstração deverá:

1. Gerar um único par de chaves Lamport.
2. Assinar duas mensagens diferentes utilizando a mesma chave.
3. Comparar os elementos secretos revelados nas duas assinaturas.
4. Identificar as posições em que os bits dos dois digests são diferentes.
5. Demonstrar que, nessas posições, foram revelados os dois elementos secretos correspondentes.

Isso evidencia por que a reutilização compromete a propriedade de uso único do esquema e pode permitir falsificações.

A demonstração deverá ser isolada do fluxo normal de assinatura. A ferramenta não deverá incentivar nem permitir silenciosamente essa reutilização em operações comuns.

---

## 5. Etapa de implementação III — Assinatura W-OTS+

Com o Lamport funcionando, o próximo passo será implementar W-OTS+.

A motivação é reduzir o tamanho das chaves e assinaturas, utilizando cadeias de funções hash em vez de revelar diretamente um elemento secreto para cada bit da mensagem.

A implementação deverá manter a mesma interface conceitual utilizada anteriormente:

- Gerar chaves.
- Assinar mensagens.
- Verificar assinaturas.

A diferença estará na construção criptográfica interna.

### 5.1. Implementação das cadeias hash

Cada elemento da assinatura W-OTS+ estará associado a uma cadeia hash.

A ideia é gerar um valor secreto inicial e aplicar sucessivas operações hash até alcançar um determinado valor público.

De forma simplificada:

\[
x_0 \rightarrow x_1 \rightarrow x_2 \rightarrow \cdots \rightarrow x_{w-1}
\]

O valor público corresponde ao final da cadeia.

Durante a assinatura, será revelado um ponto intermediário. Na verificação, o destinatário continuará a cadeia a partir desse ponto e verificará se consegue alcançar o valor público esperado.

Como o projeto utiliza W-OTS+, não basta implementar uma cadeia de hashes arbitrária: é necessário seguir a construção de funções hash com os ajustes e mecanismos de domínio e endereçamento previstos pela variante escolhida.

Essa especificação deve ser fechada antes da implementação para evitar que uma construção simplificada seja apresentada equivocadamente como uma implementação fiel de W-OTS+.

### 5.2. Conversão da mensagem para a representação em base `w`

Diferentemente do Lamport, que trabalha diretamente com os bits do digest, o W-OTS+ utiliza uma representação em base `w`.

Os valores considerados na proposta são:

\[
w \in \{4,16\}
\]

A implementação deverá transformar o digest da mensagem em uma sequência de dígitos na base escolhida.

Também será necessário calcular e acrescentar um checksum, que permite detectar a alteração dos valores utilizados nas cadeias.

O resultado será uma sequência de índices que determinará quantas operações hash serão aplicadas a cada elemento da chave durante a assinatura.

### 5.3. Geração das chaves W-OTS+

A geração deverá produzir:

1. Os elementos secretos iniciais de cada cadeia.
2. Os respectivos pontos finais, obtidos pela aplicação das funções hash.
3. A chave privada contendo os elementos secretos.
4. A chave pública contendo os pontos finais.

A quantidade de cadeias dependerá do parâmetro `w`, do tamanho do digest e do checksum.

A estrutura será parametrizada para permitir que a mesma implementação funcione com `w=4` e `w=16`.

### 5.4. Assinatura W-OTS+

Quando o usuário executar:

```bash
./lamport_sig sign --scheme wots+ --w 4 \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin
```

A ferramenta deverá:

1. Calcular o SHA-256 da mensagem.
2. Converter o digest em dígitos na base `w`.
3. Calcular o checksum.
4. Obter a sequência final de dígitos.
5. Para cada dígito, aplicar a quantidade correspondente de operações na cadeia.
6. Organizar os resultados na assinatura.

O resultado será uma sequência de valores intermediários das cadeias hash.

Assim como no Lamport, a chave privada W-OTS+ também deverá ser consumida após a assinatura. W-OTS+ continua sendo um esquema de uso único.

### 5.5. Verificação W-OTS+

Na verificação, a ferramenta repetirá a conversão do digest da mensagem e do checksum.

Para cada elemento da assinatura, aplicará as operações hash restantes até alcançar o ponto final da cadeia.

Depois, comparará todos os resultados com os elementos correspondentes da chave pública.

A assinatura será válida somente se todos os elementos forem consistentes.

### 5.6. Comparação preliminar com Lamport

Com SHA-256, considerando a representação explícita dos elementos das chaves, já é possível obter uma estimativa dos tamanhos das assinaturas:

| Esquema | Parâmetros | Elementos da assinatura | Tamanho aproximado |
|---|---|---:|---:|
| Lamport | 256 bits | 256 valores de 32 bytes | 8.192 bytes |
| W-OTS+ | `w=4` | 133 valores de 32 bytes | 4.256 bytes |
| W-OTS+ | `w=16` | 67 valores de 32 bytes | 2.144 bytes |

Esses números são estimativas do conteúdo criptográfico, sem considerar metadados dos arquivos. Eles servirão como uma referência inicial para conferir a implementação e interpretar os resultados experimentais.

**Critério para avançar:** deverá ser possível gerar uma chave W-OTS+, assinar uma mensagem, verificar uma assinatura legítima e rejeitar assinaturas adulteradas nos dois valores de `w`.

---

## 6. Etapa de implementação IV — Construção da árvore de Merkle

Esta será a etapa de integração mais importante do projeto.

Até aqui, teremos dois esquemas capazes de assinar mensagens, mas ambos possuem uma limitação fundamental: cada par de chaves só deve ser utilizado uma única vez.

A árvore de Merkle será implementada para contornar a necessidade de distribuir e autenticar individualmente cada chave pública de uso único.

A ideia é construir diversas chaves W-OTS+, utilizar cada uma como uma folha de uma árvore e publicar somente a raiz como chave pública global.

### 6.1. História da funcionalidade: geração da árvore

Imagine que o usuário execute:

```bash
./lamport_sig keygen --scheme merkle --w 4 --height 4 --out keys/
```

A ferramenta deverá criar uma árvore binária de altura `h=4`.

Uma árvore dessa altura terá:

\[
2^h = 16
\]

folhas, portanto, permitirá até 16 assinaturas independentes.

A sequência de implementação será:

**Primeiro:** gerar 16 pares de chaves W-OTS+ independentes. Cada folha terá uma chave privada e uma chave pública próprias.

**Segundo:** transformar cada chave pública W-OTS+ em um valor hash que represente sua folha na árvore. Uma possibilidade é utilizar uma árvore de compressão (*L-tree*) para transformar os elementos da chave pública W-OTS+ em um único hash de 256 bits.

**Terceiro:** construir os níveis superiores da árvore. Cada nó interno será calculado a partir dos hashes de seus dois filhos:

\[
parent = H(left \parallel right)
\]

Recomenda-se utilizar uma codificação com separação de domínio entre hashes de folhas e hashes de nós internos.

O processo será repetido até alcançar o topo da árvore.

**Quarto:** armazenar a raiz como chave pública global.

A raiz identificará e autenticará todas as chaves públicas presentes nas folhas.

```text
                ROOT
               /    \\
             H        H
            / \\      / \\
           H   H    H   H
          / \\ / \\  / \\ / \\
         ...             ...
        16 folhas W-OTS+
```

### 6.2. Estrutura da chave privada

A chave privada da construção Merkle deverá conter informações suficientes para assinar com as diferentes folhas.

Uma estrutura inicial poderá ser:

```cpp
struct MerklePrivateKey {
    uint32_t height;
    uint32_t w;

    uint64_t next_index;

    std::vector<WotsPrivateKey> leaf_keys;
};
```

A variável `next_index` identificará a próxima folha disponível.

É importante que a implementação não dependa exclusivamente de uma variável em memória. O estado deverá ser persistido no arquivo da chave privada.

Isso evita que, ao fechar e abrir novamente o programa, a ferramenta volte a utilizar uma chave que já foi consumida.

Para maior segurança, a atualização do índice deverá ser feita de maneira atômica e protegida contra operações simultâneas. Uma operação interrompida poderá desperdiçar uma folha, mas nunca deverá permitir sua reutilização.

### 6.3. História da funcionalidade: assinatura utilizando uma folha

O usuário executa:

```bash
./lamport_sig sign --scheme merkle \
    --key keys/private.key \
    --message message.txt \
    --out signature.bin
```

Nesse momento, a ferramenta deverá:

1. Ler a chave privada.
2. Consultar o próximo índice disponível.
3. Identificar a chave W-OTS+ correspondente àquela folha.
4. Assinar a mensagem utilizando essa chave.
5. Obter o caminho de autenticação da folha até a raiz.
6. Montar a assinatura final.
7. Atualizar o estado da chave privada, consumindo o índice utilizado.

A assinatura final deverá conter:

```text
MerkleSignature
├── leaf_index
├── wots_signature
└── authentication_path
```

O caminho de autenticação é uma sequência dos hashes necessários para reconstruir a raiz da árvore.

Para uma árvore de altura `h`, serão necessários exatamente `h` hashes. No nosso exemplo, com altura 4, serão necessários quatro hashes adicionais.

### 6.4. História da funcionalidade: verificação utilizando a chave global

Agora o destinatário recebe somente:

- A mensagem.
- A assinatura.
- A chave pública global, contendo a raiz da árvore.

A operação será:

```bash
./lamport_sig verify --scheme merkle \
    --key keys/public.key \
    --message message.txt \
    --signature signature.bin
```

A ferramenta deverá:

1. Ler o índice da folha utilizado na assinatura.
2. Extrair a assinatura W-OTS+.
3. Verificar a assinatura W-OTS+ e reconstruir sua chave pública.
4. Comprimir essa chave pública para obter o hash da folha.
5. Utilizar o caminho de autenticação para reconstruir a raiz da árvore.
6. Comparar a raiz calculada com a raiz armazenada na chave pública global.

Se os valores forem iguais, a assinatura será aceita. Caso contrário, será rejeitada.

O destinatário não precisa receber previamente todas as chaves públicas W-OTS+. A raiz permite autenticar a chave pública específica utilizada naquela assinatura.

### 6.5. Gerenciamento do limite de assinaturas

Como cada folha pode ser utilizada apenas uma vez, a ferramenta deverá verificar se ainda existem folhas disponíveis.

Por exemplo:

```bash
./lamport_sig status --key keys/private.key
```

Poderia produzir:

```text
Scheme: Merkle W-OTS+
Tree height: 4
Total signatures: 16
Used signatures: 3
Remaining signatures: 13
Next leaf index: 3
```

Caso todas as folhas tenham sido consumidas, uma nova operação de assinatura deverá ser rejeitada:

```text
Error: no unused one-time keys available.
```

Essa funcionalidade é especialmente importante porque a reutilização de folhas comprometeria a segurança da construção.

**Critério para avançar:** deverá ser possível gerar uma árvore, assinar mensagens utilizando folhas diferentes, verificar assinaturas utilizando somente a raiz pública e rejeitar tentativas de reutilização ou esgotamento das folhas.

---

## 7. Etapa de implementação V — Integração da ferramenta e persistência

Com os três esquemas implementados individualmente, será necessário integrar as funcionalidades em uma ferramenta única.

Até aqui, o foco terá sido construir os algoritmos. Agora, o objetivo será tornar a implementação utilizável e consistente.

### 7.1. Padronização dos comandos

A interface de linha de comando deverá possuir três operações principais:

| Comando | Responsabilidade |
|---|---|
| `keygen` | Gerar chaves para o esquema solicitado. |
| `sign` | Assinar uma mensagem utilizando a chave privada. |
| `verify` | Verificar uma assinatura utilizando a chave pública. |

Poderão ser acrescentados comandos auxiliares, como `status`, para consultar o estado das chaves de uso único.

Cada comando deverá validar seus argumentos antes de iniciar qualquer operação criptográfica.

Por exemplo, não será permitido executar uma assinatura W-OTS+ utilizando uma chave Lamport.

### 7.2. Serialização dos dados

Será necessário estabelecer um formato para armazenar e transportar as informações.

Uma assinatura não deverá depender de estruturas internas da memória do programa. Ela precisa ser serializada para que outro processo consiga interpretá-la.

Uma possível estrutura binária seria:

```text
Signature File
├── Magic Number
├── Version
├── Scheme Identifier
├── Parameters
├── Leaf Index (when applicable)
├── Signature Data
└── Authentication Path (when applicable)
```

A identificação do esquema e seus parâmetros permitirá verificar se uma assinatura foi produzida com a configuração esperada.

Também será importante validar os tamanhos dos arquivos durante a leitura. Arquivos incompletos ou malformados deverão resultar em erro, e não em comportamento indefinido.

### 7.3. Tratamento de erros

A ferramenta deverá identificar situações como:

- Arquivo de chave inexistente.
- Mensagem não encontrada.
- Assinatura inválida.
- Chave pública incompatível com o esquema.
- Parâmetros diferentes dos esperados.
- Arquivo de assinatura corrompido.
- Chave privada já utilizada.
- Árvore sem folhas disponíveis.

O objetivo é que todas as operações apresentem resultados previsíveis, mesmo quando os arquivos recebidos forem inválidos.

---

## 8. Etapa de implementação VI — Testes automatizados e validação de segurança

Com os módulos integrados, será necessário verificar se o comportamento da ferramenta corresponde ao esperado.

A proposta prevê especificamente testes para assinaturas válidas, mensagens modificadas, caminhos de autenticação inválidos e tentativas de reutilização de chaves.

Os testes serão organizados por componente.

### 8.1. Testes Lamport

| Cenário | Resultado esperado |
|---|---|
| Assinar e verificar uma mensagem válida | Aceitar |
| Alterar o conteúdo da mensagem | Rejeitar |
| Modificar um elemento da assinatura | Rejeitar |
| Utilizar uma chave pública diferente | Rejeitar |
| Utilizar uma chave privada já consumida | Rejeitar |

Também será testada a demonstração de reutilização de chaves.

### 8.2. Testes W-OTS+

| Cenário | Resultado esperado |
|---|---|
| Assinatura válida com `w=4` | Aceitar |
| Assinatura válida com `w=16` | Aceitar |
| Alteração da mensagem | Rejeitar |
| Alteração de um elemento da assinatura | Rejeitar |
| Alteração do checksum | Rejeitar |
| Utilização de parâmetros incompatíveis | Rejeitar |
| Reutilização da chave | Rejeitar |

Além disso, serão testadas as funções de conversão para base `w`, cálculo do checksum e operações nas cadeias hash.

### 8.3. Testes da árvore de Merkle

| Cenário | Resultado esperado |
|---|---|
| Assinatura válida com caminho correto | Aceitar |
| Alteração de um hash do caminho | Rejeitar |
| Alteração do índice da folha | Rejeitar |
| Utilização de uma chave pública global incorreta | Rejeitar |
| Alteração da assinatura W-OTS+ | Rejeitar |
| Reutilização de uma folha | Rejeitar |
| Tentativa de assinar após esgotar as folhas | Rejeitar |

Um cuidado adicional será testar folhas em diferentes posições da árvore. Isso permitirá identificar erros na ordem de concatenação dos hashes durante a reconstrução da raiz.

### 8.4. Testes de integração

Por fim, serão realizados testes utilizando os comandos reais da ferramenta.

Um cenário completo será:

```text
1. Gerar um par de chaves.
2. Criar uma mensagem.
3. Assinar a mensagem.
4. Verificar a assinatura.
5. Modificar a mensagem.
6. Tentar verificar novamente.
7. Confirmar a rejeição.
```

Esse fluxo será repetido para os três esquemas.

Também será importante testar se o estado das chaves Merkle permanece correto depois de encerrar e reiniciar o programa.

**Critério para avançar:** todos os testes automatizados deverão passar, incluindo casos negativos. A ferramenta deverá rejeitar entradas inválidas sem apresentar falhas de execução.

---

## 9. Etapa de implementação VII — Avaliação experimental

Com os algoritmos implementados e testados, será realizada a avaliação experimental.

Essa etapa deverá transformar as diferenças teóricas entre os esquemas em resultados mensuráveis.

A proposta estabelece duas categorias principais de comparação: tamanhos de chaves e tempos de execução das operações criptográficas.

### 9.1. Definição dos experimentos

Os experimentos serão divididos em três grupos.

#### Experimento A — Lamport OTS

Executar geração de chaves, assinatura e verificação para diversas mensagens.

Registrar:

- Tamanho da chave privada.
- Tamanho da chave pública.
- Tamanho da assinatura.
- Tempo de geração.
- Tempo de assinatura.
- Tempo de verificação.

#### Experimento B — W-OTS+

Repetir os mesmos experimentos para:

\[
w \in \{4,16\}
\]

O objetivo será observar como a escolha de `w` altera o tamanho da assinatura e o custo computacional.

#### Experimento C — Merkle + W-OTS+

Executar os experimentos com diferentes alturas da árvore.

Uma configuração inicial viável seria:

\[
h \in \{3,4,5,6\}
\]

Isso produzirá árvores com:

| Altura | Quantidade de folhas | Assinaturas disponíveis |
|---:|---:|---:|
| 3 | 8 | 8 |
| 4 | 16 | 16 |
| 5 | 32 | 32 |
| 6 | 64 | 64 |

Para cada configuração, serão registrados os tamanhos da chave privada, chave pública global e assinatura.

Também será medido o custo de geração da árvore completa.

### 9.2. Métricas e metodologia

Uma implementação de benchmark deverá executar repetidamente cada operação e armazenar os resultados em arquivos CSV.

Exemplo:

```csv
scheme,w,height,operation,time_ns,size_bytes
lamport,0,0,keygen,125000,32768
lamport,0,0,sign,80000,8192
lamport,0,0,verify,95000,0
wots,4,0,keygen,150000,8512
wots,4,0,sign,100000,4256
wots,4,0,verify,180000,0
```

Os valores acima são meramente ilustrativos.

Para tornar os resultados comparáveis, será necessário:

1. Compilar a ferramenta em modo otimizado.
2. Executar os experimentos na mesma máquina.
3. Repetir cada operação diversas vezes.
4. Evitar misturar inicializações de bibliotecas com o tempo efetivo das operações.
5. Calcular média, mediana e desvio-padrão.
6. Registrar os parâmetros utilizados em cada execução.

No caso da árvore de Merkle, há uma distinção importante: o custo de geração da árvore é diferente do custo de cada assinatura. Portanto, ambos deverão ser medidos separadamente.

Também é interessante comparar o custo total de geração da árvore com o custo amortizado por assinatura.

### 9.3. Análise dos resultados

Ao final, deverão ser produzidos gráficos comparativos:

- Tamanho das assinaturas por esquema.
- Tamanho das chaves públicas e privadas.
- Tempo de geração de chaves.
- Tempo de assinatura.
- Tempo de verificação.
- Tempo de construção da árvore em função da altura.

A discussão deverá responder a perguntas como:

1. Quanto W-OTS+ reduz o tamanho das assinaturas em relação a Lamport?
2. Qual é a diferença entre utilizar `w=4` e `w=16`?
3. Qual é o custo adicional de utilizar uma árvore de Merkle?
4. Como o aumento da altura da árvore influencia a quantidade máxima de assinaturas e o tamanho do caminho de autenticação?
5. Qual é o compromisso entre o custo inicial de geração da árvore e a possibilidade de realizar múltiplas assinaturas?

Essas perguntas orientarão a discussão do relatório final.

---

## 10. Etapa final — Documentação e entrega

A última etapa será organizar os resultados e preparar o repositório para apresentação.

O repositório deverá conter:

```text
lamport_sig/
├── src/
├── include/
├── tests/
├── experiments/
│   ├── benchmark.cpp
│   └── results/
│
├── docs/
│   ├── architecture.md
│   ├── lamport.md
│   ├── wots.md
│   └── merkle.md
│
├── CMakeLists.txt
└── README.md
```

### 10.1. README

O README deverá apresentar:

- Objetivo do projeto.
- Descrição dos três esquemas.
- Dependências necessárias.
- Instruções de compilação.
- Exemplos de utilização.
- Como executar os testes.
- Como reproduzir os experimentos.

### 10.2. Documentação criptográfica

Cada esquema deverá ter uma documentação explicando:

- Como as chaves são geradas.
- Como as assinaturas são construídas.
- Como ocorre a verificação.
- Quais são os parâmetros utilizados.
- Quais são as limitações de segurança.

A documentação da reutilização de chaves Lamport deverá receber atenção especial, pois é um dos resultados esperados da proposta.

Também deverá ficar explícito que a construção Merkle implementada é didática e não deve ser apresentada automaticamente como uma implementação completa de um padrão criptográfico de assinatura.

### 10.3. Relatório experimental

O relatório final deverá apresentar:

1. Introdução e motivação.
2. Fundamentação dos algoritmos.
3. Detalhes da implementação.
4. Metodologia experimental.
5. Resultados obtidos.
6. Análise comparativa.
7. Limitações.
8. Conclusão.

---

## 11. Cronograma sugerido de execução

Considerando um projeto de aproximadamente três semanas, sugere-se a seguinte distribuição:

| Período | Atividade | Resultado esperado |
|---|---|---|
| Dias 1–2 | Estrutura do projeto, SHA-256 e aleatoriedade | Infraestrutura funcional |
| Dias 3–5 | Implementação Lamport | Geração, assinatura e verificação |
| Dia 6 | Testes e demonstração da reutilização Lamport | Primeiro esquema validado |
| Dias 7–10 | Implementação W-OTS+ | W-OTS+ funcional para `w=4` e `w=16` |
| Dias 11–13 | Construção da árvore de Merkle | Assinatura múltipla utilizando a raiz global |
| Dia 14 | Integração com a CLI e persistência | Ferramenta integrada |
| Dias 15–16 | Testes automatizados de integração e segurança | Validação dos três esquemas |
| Dias 17–18 | Benchmarks e coleta de resultados | Dados experimentais |
| Dias 19–20 | Gráficos, análise e documentação | Relatório e documentação |
| Dia 21 | Revisão geral e preparação da apresentação | Entrega final |

---

## 12. Priorização e controle de escopo

Existe um risco importante nesse projeto: a implementação de W-OTS+ e a integração com a árvore de Merkle podem consumir mais tempo do que o esperado.

Por isso, recomenda-se estabelecer três níveis de conclusão:

| Prioridade | Funcionalidade | Critério |
|---|---|---|
| P0 — Obrigatória | Lamport completo | Gerar, assinar, verificar e demonstrar reutilização insegura |
| P1 — Obrigatória | W-OTS+ completo | Gerar, assinar e verificar para os dois parâmetros |
| P2 — Obrigatória | Merkle + W-OTS+ | Construir árvore, assinar múltiplas mensagens e verificar pela raiz |
| P3 — Complementar | CLI mais elaborada | Comandos auxiliares, informações de estado e mensagens de erro aprimoradas |
| P4 — Complementar | Experimentos adicionais | Avaliações mais extensas e configurações extras |

A principal recomendação é **não começar pela árvore de Merkle**. Ela depende do funcionamento correto do W-OTS+, que, por sua vez, depende da infraestrutura de hash e geração de chaves. Implementar a árvore antes de validar os componentes anteriores tornaria a depuração muito mais difícil.

Também se recomenda não investir excessivamente na interface de linha de comando antes de ter os três esquemas funcionando. Uma CLI básica é suficiente durante o desenvolvimento.

---

## 13. Definição de pronto (*Definition of Done*)

Ao final do trabalho, a ferramenta deverá atender aos seguintes requisitos:

| Requisito | Condição de conclusão |
|---|---|
| Infraestrutura criptográfica | SHA-256 e aleatoriedade segura funcionando |
| Lamport OTS | Geração, assinatura e verificação funcionando |
| W-OTS+ | Geração, assinatura e verificação para `w=4` e `w=16` |
| Árvore de Merkle | Construção de folhas e nós internos funcionando |
| Assinatura múltipla | Várias mensagens assinadas com folhas diferentes |
| Chave pública global | Verificação utilizando somente a raiz e os dados da assinatura |
| Controle de reutilização | Impedir reutilização acidental de chaves de uso único |
| Testes | Casos positivos, negativos e de segurança automatizados |
| Interface | CLI para geração, assinatura e verificação |
| Benchmark | Comparação de tamanhos e tempos |
| Documentação | Instruções de uso e explicação das construções |

---

## 14. Considerações técnicas importantes

Antes de começar a implementação, é importante fechar quatro decisões:

**1. Especificação do W-OTS+.** Definir exatamente qual construção será seguida, especialmente a implementação das funções hash com endereçamento e máscaras. Essa é uma parte que merece atenção para não implementar somente uma variação simplificada de WOTS e chamá-la de W-OTS+.

**2. Construção das folhas Merkle.** Definir como os elementos da chave pública W-OTS+ serão condensados em um único hash de folha. O uso de uma L-tree é uma escolha adequada para essa construção.

**3. Persistência do estado.** A chave privada Merkle precisa registrar quais folhas já foram utilizadas. Uma restauração de um arquivo antigo de chave privada pode provocar reutilização, portanto a documentação deve deixar essa limitação explícita.

**4. Representação das chaves.** Definir se as chaves privadas serão armazenadas integralmente ou derivadas de uma semente mestra. Essa escolha altera significativamente o tamanho dos arquivos e deverá ser considerada na interpretação dos benchmarks.

---

## 15. Fluxo de desenvolvimento resumido

Para visualizar a implementação como uma sequência de funcionalidades, o desenvolvimento seguirá esta história:

```text
                 INÍCIO DO PROJETO
                        |
                        v
              Criar infraestrutura
                SHA-256 + RNG
                        |
                        v
                Implementar Lamport
                        |
              +---------+---------+
              |                   |
              v                   v
         Gerar chaves        Assinar mensagem
              |                   |
              +---------+---------+
                        |
                        v
                 Verificar assinatura
                        |
                        v
               Testar reutilização
                        |
                        v
                 Implementar W-OTS+
                        |
              +---------+---------+
              |                   |
              v                   v
           w = 4                w = 16
              |                   |
              +---------+---------+
                        |
                        v
              Implementar Merkle
                        |
                        v
             Gerar folhas W-OTS+
                        |
                        v
                Construir árvore
                        |
                        v
              Obter raiz global
                        |
                        v
              Implementar assinatura
                  com índice
                        |
                        v
             Implementar verificação
              pelo caminho Merkle
                        |
                        v
               Integrar com a CLI
                        |
                        v
               Testes automatizados
                        |
                        v
                Benchmarks
                        |
                        v
             Documentação e relatório
                        |
                        v
                   ENTREGA
```

---

## 16. Recomendação final

Trate o projeto como três implementações criptográficas progressivamente integradas, e não como três funcionalidades independentes. Lamport será a primeira referência funcional; W-OTS+ será a evolução que reduz o tamanho das assinaturas; e Merkle será a construção que transforma as assinaturas de uso único em uma ferramenta capaz de autenticar múltiplas mensagens por meio de uma única chave pública global.

Essa organização torna o desenvolvimento mais previsível, facilita a identificação de erros e permite obter resultados parciais demonstráveis mesmo antes de concluir a integração final.
