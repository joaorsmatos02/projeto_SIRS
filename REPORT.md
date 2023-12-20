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
Comunicação segura é uma parte vital da arquitetura de segurança, assegurando a troca de dados confidenciais entre entidades, incluindo comunicações Cliente <-> Servodor e Servidor-Base de Dados. A nossa implementação adota uma abordagem baseada em sockets SSL (Secure Sockets Layer) para garantir as propriedades de segurança pretendidas perante as informações a serem transmitidas. Abaixo, descrevemos as estratégias e desafios associados a esta implementação.
Primeiramente, é de grande relevância relatar o trabalho de administrador de sistemas que será necessário executar, de modo a obter o bom funcionamento do sistema. Mais precisamente, foi necessário executar as seguintes ações: (Nota: tal trata-se de um trabalho ao encargo de um administrador de sistemas, onde este o executa excecionalmente, numa fase prévia ao respetivo deployment da aplicação)
Foi utilizada a ferramenta de gestão de chaves e certificados, parte do JDK, keytool.
(SERVIDOR)
1 – Gerar Keystore do Servidor juntamente com a geração do par de chave pública e privada RSA do mesmo
- keytool -genkeypair -alias serverRSA -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore serverKeyStore
  2 – Extrair o Certificado associado à chave pública do Servidor
  - keytool -exportcert -alias serverrsa -storetype PKCS12 -keystore serverKeyStore -file serverCert.cer
  2.1 – Este Certificado é guardado num diretório denominado CAserver, de forma a simular uma Certification Authority, ou seja, este pode ser considerado um certificado de confiança.
  3 – Gerar Truststore do Servidor vazia (necessário iniciar com uma chave, mas é apagada de seguida)
  - keytool -genseckey -alias toDeleteKey -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverTrustStore
- keytool -delete -alias toDeleteKey -storetype PKCS12 -keystore serverTrustStore
  4 – Gerar chaves simétricas assumidas pelo enunciado. Existência de uma por conta, apenas conhecida por Cliente + Dispositivo e Servidor. Utilizadas na comunicação Cliente <-> Servidor. Exemplo de geração:
  - keytool -genseckey -alias alice_iphone_secret -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverKeyStore
- keytool -genseckey -alias alice_computador_secret -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverKeyStore
  5 – Uma vez assumido o conhecimento de chaves simétricas entre Cliente e Banco, foram, também, previamente geradas as chaves simétricas associadas à conta e não ao Cliente + dispositivo. Mais precisamente, cada conta terá uma chave simétrica conhecida apenas pelo Servidor e Base de Dados, de forma a habilitar a comunicação segura entre estes. Exemplo de geração:
  - keytool -genseckey -alias alice_account_secret -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverKeyStore
    (Para contas partilhadas)
-	keytool -genseckey -alias alice_bob_account_secret -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverKeyStore
     6 – Gerar e adicionar chave simétrica conhecida entre Servidor e Base de Dados à Keystore do Servidor.
     - keytool -genseckey -alias server_db_secret -keyalg AES -keysize 256 -storetype PKCS12 -keystore serverKeyStore

(Base de Dados)
7 - Gerar Keystore da Base de Dados juntamente com a geração do par de chave pública e privada RSA do mesmo.
- keytool -genkeypair -alias dataBaseRSA -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore dataBaseKeyStore
8 - Extrair o Certificado associado à chave pública da Base de Dados
- keytool -exportcert -alias databasersa -storetype PKCS12 -keystore dataBaseKeyStore -file dataBaseCert.cer
9 - Copiar chave simétrica server_db_secret para Keystore (realizado em tempo de execução, não realizado pelo administrador de sistemas, mas importante fazer referência, também, aqui. A ser abordado mais à frente).
10 - Gerar Truststore da Base de Dados vazia (necessário iniciar com uma chave, mas é apagada de seguida)
- keytool -genseckey -alias toDeleteKey -keyalg AES -keysize 256 -storetype PKCS12 -keystore dataBaseTrustStore
- keytool -delete -alias toDeleteKey -storetype PKCS12 -keystore dataBaseTrustStore
  11 - Importar certificado da Base de Dados para a TrustStore do Servidor
  - keytool -importcert -alias databasersa -file ../../DataBase/dataBaseKeyStore/dataBaseCert.cer -storetype PKCS12 -keystore serverTrustStore
  12 - Importar certificado do Servidor para a TrustStore da Base de Dados
  - keytool -importcert -alias serverrsa -file ../../CAserver/serverCert.cer -storetype PKCS12 -keystore dataBaseTrustStore

Posto isto, é agora importante realçar o porquê das escolhas tomadas. A decisão de utilizar a ferramenta keytool para a geração de chaves simétricas e assimétricas é respaldada por diversos motivos que contribuem para a segurança e interoperabilidade do sistema. Para chaves assimétricas, utilizou-se o algoritmo RSA, sendo este amplamente utilizado para criptografia assimétrica, acabando por oferecer robustez em termos da obtenção de uma comunicação segura entre entidades. O tamanho de 2048 bits é considerado seguro e é uma escolha comum para aplicações que exigem um equilíbrio entre segurança e desempenho. Relativamente às chaves simétricas, foi utilizado o algoritmo AES com 256 bits, pelos mesmos motivos anteriormente referidos. A escolha do formato PKCS12 para armazenamento de chaves no sistema foi fundamentada em benefícios significativos como portabilidade, já que se trata de um formato amplamente aceite, proporcionando portabilidade e interoperabilidade além do ecossistema Java. Este também suporta o armazenamento de diferentes dados de segurança e define a necessidade de autenticação, via password, de forma aceder ao seu conteúdo.
Com isto, dá-se por concluído o trabalho inicial do admnistrador de sistemas.

Passando agora à explicação da implementação do código-fonte responsável por, em conjunto com os SSL Sockets, assegurar a confidencialidade, integridade e autenticidade das informações transmitidas. A classe SecureMessageLib desempenha um papel crucial na garantia de comunicações seguras sobre sockets SSL. Os principais aspetos da implementação:
- Cifragem de Mensagens: o método protectMessage é responsável por cifrar uma mensagem antes de ser enviada. Utiliza uma chave secreta compartilhada entre duas entidades apenas, obtida a partir de uma keystore segura. A cifragem é realizada com o algoritmo AES em modo CBC (Cipher Block Chaining), de forma a garantir confidencialidade (decisão com o mesmo fundamento anteriormente apresentado). De forma a garantir integridade e autenticidade da mensagem a ser transmitida, é feita uma assinatura, a partir da chave privada do emissor em questão, aos dados cifrados (ou melhor, ao hash dos dados cifrados). Esta é, consequentemente, concatenada a estes para posterior verificação. Posto isto, é feita a codificação para Base64 dos dados em questão.
- Verificação de Assinatura Digital: O método unprotectMessage decifra e autentica mensagens recebidas. Este divide a mensagem recebida em duas partes, as quais, a com o conteúdo cifrado, e a com a respetiva assinatura. Primeiramente, verifica-se a integridade e autenticidade dos dados recebidos, a partir do método Signature.verify, onde este verifica a assinatura digital utilizando a chave pública do remetente, garantindo assim as propriedades pretendidas, inclusive o não-repúdio. Caso seja verificado, é então feita a decifra dos dados (com tudo o que essa ação implica, extração de IV, etc. – já explicado na secção 2.1.2).
Nota: Foi utilizada a mesma lógica e algoritmos de cifra, decifra, IV e assinatura nas duas libs desenvolvidas, daí a carência de detalhe nesta secção.

Agora, individualmente, serão expostas as diferentes abordagens tidas para com as diferentes entidades comunicadoras.
- Comunicação Servidor <-> Base de Dados: a Base de Dados disponibiliza um SSL Socket, configurado com a sua respetiva Keystore, de forma a autenticar-se perante quem se conecta a este. Para tal, utilizou-se System.setProperty("javax.net.ssl.keyStoreType", "PKCS12"); System.setProperty("javax.net.ssl.keyStore", keyStorePath); System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);. No contexto da comunicação com a base de dados, o servidor adota uma abordagem segura ao incorporar um SSL Socket, estabelecendo assim uma conexão protegida. Este mecanismo essencial garante não apenas a confidencialidade, mas também a integridade e autenticidade das transmissões de dados. Para possibilitar essa comunicação segura, são empregadas propriedades fundamentais, nomeadamente, Keystore e Truststore. A Keystore é utilizada pelo servidor para se autenticar perante a Base de Dados, enquanto a Truststore desempenha um papel crucial ao verificar a autenticidade da fonte de dados da base de dados. Noutras palavras, a Truststore valida se a Base de Dados é uma fonte confiável, proporcionando assim uma camada adicional de segurança. Uma vez que o estabelecimento desta comunicação necessita da autenticação por parte das duas entidades envolventes, o Servidor necessita, ao conectar-se, de enviar o seu respetivo Certificado, bem como o HMAC do mesmo, calculado a partir da chave simétrica conhecida apenas pelo Servidor e Base de Dados (Nota: referir que esta chave simétrica é inserida na Keystore da Base de Dados em tempo de execução, aquando executado o código-fonte relativo ao Servidor, uma vez que tal não foi realizado em trabalho de administrador de sistemas, por falta de capacidades). Tanto o Certificado, como o respetivo HMAC deste, são enviados em claro, através do SSL Socket, uma vez que apenas se pretende obter a propriedade de integridade no envio deste, já que se trata de um identificador público, conhecido por todos. Uma vez recebidos, a Base de Dados encarrega-se de verificar a integridade do certificado, comparando o resultado relativo ao HMAC recebido, com o calculado por si, a partir da chave simétrica alocada na sua keystore (apenas conhecida por esta e pelo Servidor). Se for verificado, este compara o certificado recebido com o único certificado que contém na sua Truststore, no caso, o referente ao Servidor. Após tal procedimento, para qualquer troca de ficheiros entre as entidades envolventes, é utilizada a biblioteca SecureDocumentLib, de forma a proteger/desproteger o ficheiro JSON a ser transmitido. Consequentemente, este é codificado/descodificado em Base64 e, posteriormente, protegido/desprotegido através da utilização da biblioteca SecureMessageLib. Já a troca de mensagens, mais precisamente, quando não são transmitidos ficheiros, mas apenas pedidos/informações apenas é utilizada a biblioteca SecureMessageLib.

- Comunicação Cliente <-> Servidor: O Servidor disponibiliza um SSL Socket, configurado com a sua respetiva Keystore, de forma a autenticar-se perante quem se conecta a este. Para tal, utilizaram-se as propriedades semelhantes às já referidas acima. No contexto da comunicação com o Servidor, o Cliente adota uma abordagem segura ao incorporar um SSL Socket, estabelecendo assim uma conexão protegida. Antes da conexão ser estabelecida, é verificado se o Cliente se encontra a conectar-se num dispositivo novo. Se sim, são geradas, em tempo de execução, as chaves RSA correspondentes a este novo dispositivo. Estas são guardadas na sua respetiva keystore (numa pasta segura do dispositivo, sem acessos partilhados). Depois, novamente em tempo de execução, é, também, inserida a chave simétrica (associada ao novo dispositivo) conhecida apenas entre o Cliente + dispositivo e Servidor na respetiva keystore. Consequentemente, é criada a Truststore do Cliente, onde nesta é importado o Certificado do Servidor, presente no diretório CA, simulando um certificado autenticado por esta. Posto isto, é aplicada uma lógica semelhante à acima abordada relativamente ao processo de envio do certificado e respetivo cálculo de HMAC, a partir da chave simétrica conhecida pelo Cliente e Servidor apenas, para o Servidor. Mais precisamente, o Cliente envia-os e, aquando receção, o Servidor faz a verificação de integridade já explicada anteriormente. Caso seja verificada a integridade do certificado, este é guardado na Truststore do Servidor para futuras verificações relacionadas com assinaturas. Após este procedimento, ou caso não seja um novo dispositivo, é procedida a comunicação entre as duas entidades através da biblioteca SecureMessageLib, mais exatamente, todos os pedidos e respostas são protected/unprotected através dos métodos já explicados acima.
  Em conclusão, a implementação efetiva destas práticas de segurança possibilitou a criação de um ambiente robusto e confiável, essencial para proteger a confidencialidade, integridade, autenticidade e não repúdio das informações transmitidas em ambas as direções: Servidor <-> Base de Dados e Cliente <-> Servidor.

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
