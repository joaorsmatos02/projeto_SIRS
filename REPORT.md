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
A opção de criptografia em duas camadas é introduzida de forma a garantir as propriedades de segurança até aqui prometidas. Mais precisamente, esta permite a criptografia individual dos atributos que compõe o ficheiro responsável pelo armazenamento de dados (à exceção do atributo accountHolder), ainda antes de realizar a criptografia completa do documento. Esta abordagem é útil e foi concebida para que, na troca de informações entre Servidor e Base de Dados (e vice-versa), a autenticidade do emissor seja verificada, mas os respetivos valores não possam ser acessíveis. Mais precisamente, caso a opção de twoLayerEncryption seja ativada, os valores dos atributos do documento são cifrados com a chave simétrica associada à respetiva conta do cliente. Consequentemente, os bytes relativos ao documento cifrado (primeira camada) são, uma segunda vez, cifrados, mas agora, a partir da chave simétrica conhecida apenas pelo Servidor e Base de Dados. 
Esta medida garante confidencialidade.

#### - Assinatura:
Incluiu-se a assinatura do documento cifrado a partir de chaves assimétricas, mais precisamente, dependendo do emissor (Servidor ou Base de Dados), este é assinado com a chave privada do próprio. Assim, aquando receção do documento, o recetor passa a ter capacidade de verificar a assinatura com base na chave pública correspondente ao certificado do emissor presente na sua truststore.
De forma a garantir freshness, evitando assim ataques de replay, ao documento assinado é lhe associado um valor TimeStamp para que, aquando receção do documento, possa ser feita uma verificação de já existência deste. Mais exatamente, na receção, é feita uma primeira verificação que consiste em descartar payloads com um valor TimeStamp associado de há mais de dez segundos comparativamente ao tempo atual da máquina a executar o processo de verificação. Esta flexibilidade/gap temporal existe na medida de precaver possíveis dessincronizações de relógios entre máquinas em comunicação. Caso a TimeStamp associada esteja dentro do intervalo aceitável, é feita uma verificação numa tabela que guarda os últimos payloads recebidos nos últimos, também, dez segundos. Caso o mesmo payload se encontre na tabela, este é rejeitado, caso contrário é aceite e adicionado.
Esta medida garante autenticidade.


[userAccountDocFormat.png]

(_Outline the design of your custom cryptographic library and the rationale behind your design choices, focusing on how it addresses the specific needs of your chosen business scenario._)

(_Include a complete example of your data format, with the designed protections._)

#### 2.1.2. Implementation

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
