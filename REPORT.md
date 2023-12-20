#  BlingBank

## 1. Introdução
O banco digital BlingBank destaca-se como um símbolo de acessibilidade e conveniência. A nossa plataforma bancária online capacita os utilizadores com funcionalidades robustas, tais como monitorização de despesas e pagamentos, verificação de saldo, execução de pagamentos e movimentos através de contas singulares e partilhadas. Para reforçar a segurança dos dados financeiros dos nossos utilizadores, desenvolvemos um projeto meticulosamente concebido para garantir os princípios de confidencialidade, integridade (inclusive deteção e respetiva rejeição de pagamentos que representem replay attacks), autenticidade e não repúdio para todas as transações.

O nosso desafio de segurança primordial centra-se na implementação de medidas rigorosas para garantir a atualidade das ordens de pagamento, mitigando o risco de execuções duplicadas. Cada transação deve ser um registo irrefutável, impedindo qualquer repúdio de ações. Além disso, para contas com vários titulares, é necessária uma abordagem mais exigente, requerendo autorização e não repúdio de todos os titulares de conta antes de executar uma ordem de pagamento.

Para atender a estes padrões de segurança elevados, reconhecemos a necessidade de duas bibliotecas criptográficas. Como explicitado no enunciado, assumimos a existência de chaves simétricas entre Banco e Cliente. Dada a necessidade de criação do par de chaves pública/privada para cada cliente (por dispositivo diferente), tal incluiu o desenvolvimento de novas chaves para os utilizadores, garantindo uma distribuição dinâmica de chaves que esteja alinhada com o nosso compromisso de proteger a integridade financeira e a confiança dos nossos utilizadores.


(_Provide a brief overview of your project, including the business scenario and the main components: secure documents, infrastructure, and security challenge._)

(_Include a structural diagram, in UML or other standard notation._)

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design
A biblioteca criptográfica foi projetada para atender às exigências especificada no cenário de negócios da BlingBank, que se concentra em garantir a confidencialidade, autenticidade e não repúdio das transações financeiras. Abaixo, um esboço do design, destacando as principais escolhas e respetivas justificações:
##### - Estrutura Hierárquica do Documento:
Primeiramente, definiu-se como formato de documento o tipo JSON, de forma a representar as diferentes informações de uma conta bancária, como titulares, saldo, movimentos e detalhes de pagamento. Ainda que cifrado, o documento é armazenado na Base de Dados na forma:
[img/userAccountDBDocFormat.png]

Como verificável na imagem acima, o secure document é mantido num estado cifrado, mas com a estrutura original concebida. De notar que apenas o atributo accountHolder tem valor não cifrado, esta escolha tem fundamento na possibilidade de execução de queries à Base de Dados (a partir do valor associado a este atributo).

##### - Criptografia em Duas Camadas:
A opção de criptografia em duas camadas é introduzida de forma a garantir as propriedades de segurança até aqui prometidas. Mais precisamente, esta permite a criptografia individual dos atributos que compõe o ficheiro responsável pelo armazenamento de dados (à exceção do atributo accountHolder), ainda antes de realizar a criptografia completa do documento. Esta abordagem é útil e foi concebida para que, na troca de informações entre Servidor e Base de Dados (e vice-versa), a autenticidade do emissor seja verificada, mas os respetivos valores não possam ser acessíveis. Mais precisamente, caso a opção de twoLayerEncryption seja ativada, os valores dos atributos do documento são cifrados com a chave simétrica associada à respetiva conta do cliente. Consequentemente, os bytes relativos ao documento cifrado (primeira camada, onde key é mantido em claro, mas value é cifrado) são, uma segunda vez, cifrados, mas agora, a partir da chave simétrica conhecida apenas pelo Servidor e Base de Dados. A ideia é que, no processo de decifra, do lado da Base de Dados, apenas seja possível decifrar a primeira camada, mantendo a confidencialidade dos valores armazenados (cifrados com a chave de conta, desconhecida pela Base de Dados). Já do lado do Servidor, este tem a capacidade de fazer a decifra das duas camadas, de modo a que seja possível processar certas operações lógicas necessárias.
Esta medida garante confidencialidade.

#### - Assinatura:
Incluiu-se a assinatura do documento cifrado a partir de chaves assimétricas, mais precisamente, dependendo do emissor (Servidor ou Base de Dados), este é assinado com a chave privada do próprio. Assim, aquando receção do documento, o recetor passa a ter capacidade de verificar a assinatura com base na chave pública correspondente ao certificado do emissor presente na sua truststore.
De forma a garantir freshness, evitando assim ataques de replay, ao documento assinado é lhe associado um valor TimeStamp para que, aquando receção do documento, possa ser feita uma verificação de já existência deste. Mais exatamente, na receção, é feita uma primeira verificação que consiste em descartar payloads com um valor TimeStamp associado de há mais de dez segundos comparativamente ao tempo atual da máquina a executar o processo de verificação. Esta flexibilidade/gap temporal existe na medida de precaver possíveis dessincronizações de relógios entre máquinas em comunicação. Caso a TimeStamp associada esteja dentro do intervalo aceitável, é feita uma verificação numa tabela que guarda os últimos payloads recebidos nos últimos, também, dez segundos. Caso o mesmo payload se encontre na tabela, este é rejeitado, caso contrário é aceite, processado e adicionado à tabela.
Esta medida garante autenticidade.


[userAccountDocFormat.png]

(_Outline the design of your custom cryptographic library and the rationale behind your design choices, focusing on how it addresses the specific needs of your chosen business scenario._)

(_Include a complete example of your data format, with the designed protections._)

#### 2.1.2. Implementation
Nesta seção, discutiremos as escolhas de implementação fundamentais que orientam o desenvolvimento da biblioteca criptográfica. Cada decisão será cuidadosamente justificada com base nos requisitos específicos do cenário de negócios em questão. Foi utilizada a linguagem Java para o desenvolvimento da biblioteca.
Primeiramente, de forma a construir uma instância de SecureDocumentLib, são necessários três argumentos, dos quais, keyStoreName, keyStorePass, keyStorePath. Estes representam o conjunto de variáveis necessárias para a garantia de acesso à keystore necessária, no caso, a keystore que contém as chaves a serem utilizadas no processo de cifra e decifra de documentos.
Relativamente ao processo de cifra de documentos (método protect), este funciona da forma: é inicialmente verificado se a cifra é de uma, ou duas camadas. De notar que o Servidor executa sempre cifra de duas camadas, enquanto a Base de Dados executa sempre apenas uma camada, a mais exterior (a ser explicado abaixo). Caso estejamos perante o caso de dupla cifra, é feita uma segunda verificação, desta vez, relativamente ao tipo de documento a cifrar, mais precisamente, este pode tratar-se de um documento de conta (geral), ou de um documento relativo aos pagamentos associados a uma dada conta. Esta distinção deve-se à característica fundamental da opção de dupla cifra, já que, nesse caso, os valores associados às chaves do ficheiro JSON são cifrados individualmente o que, naturalmente, obriga a uma distinção, dada a diferença dos atributos que compõem cada ficheiro JSON. De forma a cifrar os valores associados às chaves do ficheiro a ser protegido (à exceção da chave accountHolder, já explicado acima), é, inicialmente, obtida a chave simétrica associada à conta em questão, esta apenas conhecida entre utilizadores de conta e o próprio banco. Esta encontra-se guardada na keystore do Servidor (assumido pelo enunciado). Uma vez na posse da chave simétrica, é iniciado, de facto, o processo de cifra, para tal, foi utlizado o algoritmo AES em modo CBC (Cipher Block Chaining) com preenchimento PKCS5Padding. A justificação do uso deste algoritmo advém de vários fatores, dos quais, resistência a padrões repetitivos, dado o uso de IV; É, também, oferecido por este uma segurança adicional, na medida em que o mesmo incorpora o bloco cifrado anterior no processo de encriptação do bloco atual, adicionando uma camada adicional de complexidade. Importante ter em conta que, devido a esta característica, o processo de cifra é sujeito a que, caso ocorra um erro num dado bloco, todos os blocos subsequentes serão afetados por tal, mais, tal característica, impossibilita a paralelização deste processo, contudo, pelo enorme requisito de necessidade de segurança dos dados em questão, é algo que concordámos suportar. O processo em mais detalhe abaixo.
- Geração de IV (Vetor de Inicialização):
- Um Initialization vector (IV) é gerado aleatoriamente com 16 bytes de comprimento. Este é essencial para garantir que textos idênticos não resultem em cifras idênticas, o que, consequentemente, aumenta a segurança do processo, principalmente contra ataques de análise.
- Execução da cifra em cada valor associado a uma chave. Este valor cifrado (bytes) é, noutra camada, codificado em Base64 e armazenado no valor do respetivo atributo associado ao objeto JSON a cifrar.
- Concatenação do valor correspondente ao IV a um valor do documento:
- O IV e o valor balance associado à conta (já cifrado com este algoritmo) são concatenados. Esta concatenação tem como intuito facilitar a transmissão e o armazenamento do IV junto com o conteúdo cifrado.
  Com isto, dá-se o fim da cifra de primeira camada (interior)

Relativamente à segunda camada, esta utiliza exatamente o mesmo algoritmo de cifra abordado anteriormente, pelas mesmas justificações. Contudo, neste caso, o processo de cifra é aplicado aos bytes relativos ao objeto JSON onde, neste, já terá sido aplicado a primeira camada de cifra. Importante referir que a chave simétrica utilizada para este processo é a conhecida entre Servidor e Base de Dados, apenas. Até este ponto, garantiu-se a propriedade de confidencialidade. Relativamente às restantes propriedades pretendidas, estas foram obtidas da seguinte forma: Primeiramente, é verificado, a partir dos atributos relacionados à keystore - pertencentes à instância SecureDocumentLib em uso, quem está a executar o processo de cifra (Servidor ou Base de Dados), consoante tal, é obtida, a partir da sua respetiva keystore, a chave (assimétrica) privada deste. O objetivo deste procedimento é garantir a propriedade de autenticidade, da forma: Dado o objeto cifrado + codificado em Base64 e uma TimeStamp (a do exato momento de execução), estes permitem construir uma instância de um SecureDocumentDTO onde, consequentemente, é assinado a partir da chave privada obtida anteriormente. Mais precisamente, é utilizada a classe Signature da linguagem Java, a partir da criação de uma instância “SHA256withRSA”. A escolha do algoritmo "SHA256withRSA" baseou-se na necessidade de utilização do algoritmo de hash SHA-256, de forma a gerar um resumo criptográfico dos dados e, em seguida, assinar esse resumo a partir da chave privada RSA. Esta decisão deve-se muito ao facto do algoritmo de hash utilizado ser considerado um dos mais seguros atualmente, dada a sua grande capacidade de prevenção de tentativas de “reverse back” dos valores originais e, também, devido à sua resistência a colisões. A manipulação de chaves privadas requer um cuidado e proteção adequada, uma vez que a comprometimento da chave privada comprometeria a segurança do processo de assinatura. O resultado final é um objeto assinado digitalmente que pode ser transmitido ou armazenado com a garantia de integridade e autenticidade dos dados contidos no objeto original. Recapitulando, uma instância SecureDocumentDTO é assinada da forma abordada acima e, consequentemente, adicionada a uma, outra, instância SignedObjectDTO composta pelo objeto assinado e respetivo certificado referente à chave privada usada na assinatura. Esta decisão tem fundamento na necessidade de obtenção do certificado, de modo a ser possível executar o método check (também presente na biblioteca) com fim a verificar a integridade e autenticidade do objeto assinado. O valor Timestamp presente no objeto SecureDocumentDTO será explicado abaixo, aquando menção do método check.
Relativamente ao método unprotect, este, naturalmente, executa o processo reverso do método protect. Contudo será importante referir alguns detalhes mais característicos deste, como a necessidade de extração dos primeiros 16 bytes referentes ao valor do IV (128 bits para o modo de operação CBC (Cipher Block Chaining)), necessário para o processo de decifra. E, caso se trate de decifra de duas camadas, é executado o mesmo processo, mas agora retirando os 16 bytes relativos ao IV, do valor do atributo balance (no caso do ficheiro ser do tipo account) e, consequentemente, já com tudo o necessário, executar o processo de decifra, individualmente, para cada valor. À medida que os valores são decifrados, o objeto JSON é construído com os respetivos valores em claro.
Por fim, será importante abordar o método check, este tem como papel principal verificar a integridade de um dado payload, mais precisamente, verificar a assinatura digital de um SignedObject e validar a TimeStamp associada a esse. Abaixo seguem os detalhes sobre os métodos utilizados, as bibliotecas envolvidas e as justificações para essas escolhas. Utilização de SHA256withRSA por razões relativas à decisão tomada no método protect. Foi utilizada a função verify, chamada no objeto signedObject, pertencente à instância signedObjectDTO, com a chave pública contida no certificado, também pertencente à instância signedObjectDTO. Tal procedimento verifica se a assinatura digital é válida, ou seja, se o payload não foi alterado e se este foi assinado pela entidade correspondente à chave privada associada à chave pública contida no certificado. Se tal se verificar, é ainda realizada uma segunda verificação, esta consiste em, finalmente, utilizar o valor TimeStamp associado ao SecureDocumentDTO, mais exatamente, verifica se o timestamp associado ao documento é válido, ou seja, se não expirou e se não foi anteriormente processado. Ou seja, verifica se esse valor de TimeStamp já ultrapassa dez segundos comparativamente ao instante atual da execução (valor alargado, mas neste é tido em conta possíveis dessincronizações de relógio entre máquinas em comunicação – basicamente trata-se do limite de tempo em que um payload pode demorar a ser comunicado a partir da máquina Cliente até à sua receção na máquina Servidor), se sim, o payload é descartado, caso contrário, é feita uma nova verificação num HashSet, mais precisamente, este é composto pelas entradas recebidas nos últimos dez segundos, ou seja, uma entrada apenas permanece neste Set por dez segundos, tal tem como objetivo suprimir o tempo necessário para realizar esta nova verificação, evitando assim uma possível extensibilidade absurda deste. Esta medida tem como principal fundamento a prevenção de replay attacks.
No âmbito da implementação da biblioteca criptográfica, destacamos a prática consistente de utilizar o método protect no servidor, ativando a cifra dupla por meio da flag correspondente. Essa prática visa garantir a confidencialidade dos dados ao armazená-los na base de dados, onde a decifra dupla é desativada durante a operação unprotect. Essa abordagem estratégica assegura que a camada interna, contendo informações sensíveis, permaneça opaca para a base de dados, preservando a confidencialidade dos dados cifrados. Um aspeto crucial é a assinatura da cifra exterior, introduzindo um mecanismo robusto de autenticação. A assinatura, realizada durante o processo de proteção, permite a verificação eficaz da autenticidade dos dados. Ao empregar a assinatura digital, criamos uma camada adicional de segurança, assegurando que a integridade e autenticidade dos dados seja verificada, mesmo quando são manipulados em diferentes partes do sistema.


(_Detail the implementation process, including the programming language and cryptographic libraries used._)

(_Include challenges faced and how they were overcome._)

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

(_Provide a brief description of the built infrastructure._)

(_Justify the choice of technologies for each server._)

#### 2.2.2. Server Communication Security


(_Discuss how server communications were secured, including the secure channel solutions implemented and any challenges encountered._)

(_Explain what keys exist at the start and how are they distributed?_)

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

(_Describe the new requirements introduced in the security challenge and how they impacted your original design._)

#### 2.3.2. Attacker Model

(_Define who is fully trusted, partially trusted, or untrusted._)

(_Define how powerful the attacker is, with capabilities and limitations, i.e., what can he do and what he cannot do_)

#### 2.3.3. Solution Design and Implementation

(_Explain how your team redesigned and extended the solution to meet the security challenge, including key distribution and other security measures._)

(_Identify communication entities and the messages they exchange with a UML sequence or collaboration diagram._)  

## 3. Conclusion

(_State the main achievements of your work._)

(_Describe which requirements were satisfied, partially satisfied, or not satisfied; with a brief justification for each one._)

(_Identify possible enhancements in the future._)

(_Offer a concluding statement, emphasizing the value of the project experience._)

## 4. Bibliography

(_Present bibliographic references, with clickable links. Always include at least the authors, title, "where published", and year._)

----
END OF REPORT
