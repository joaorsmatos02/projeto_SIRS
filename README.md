# A09 BlingBank Project Read Me

<!-- this is an instruction line; after you follow the instruction, delete the corresponding line. Do the same for all instruction lines! -->

## Team

| Number  | Name           | User                                  | E-mail                                        |
| --------|----------------|---------------------------------------|-----------------------------------------------|
| 110996  | Diogo Pereira  | https://github.com/diogo02pereira   | <mailto:diogo.m.pereira@tecnico.ulisboa.pt>   |
| 110846  | João Matos     | https://github.com/joaorsmatos02      | <mailto:joao.silva.matos@tecnico.ulisboa.pt>  |
| 110947  | João Santos    | https://github.com/joaogoncalosantoss | <mailto:joaogoncalosantos@tecnico.ulisboa.pt> |


![Diogo Pereira](img/diogo_pereira.jpeg) ![João Matos](img/joao_matos.jpg) ![João Santos](img/joao_santos.png)

## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it is necessary to setup a virtual environment, with N networks and M machines.  

The following diagram shows the networks and machines:

![Network Diagram](img/network.png)

### Prerequisites

All the virtual machines are based on: Linux 64-bit, Kali 2023.3  

[Download](https://www.kali.org/get-kali/#kali-platforms) and [install](https://www.kali.org/docs/installation/hard-disk-install/) a virtual machine of Kali Linux 2023.3.  
Clone the base machine to create the other machines.

### Machine configurations

For each machine, there is an initialization script with the machine name, with prefix `init-` and suffix `.sh`, that installs all the necessary packages and makes all required configurations in the a clean machine.

Inside each machine, use Git to obtain a copy of all the scripts and code.

```sh
$ git clone https://github.com/tecnico-sec/a09-diogo-joao-joao.git
```

Next we have custom instructions for each machine.

#### Machine 1

This machine runs a database server that connects to MongoDB.
Ideally this machine would run MongoDB locally and not have the need to connect to the internet, however we were
unable to install the database locally, so the network scheme had to be adapted around this.

#### Machine 2

This machine runs the main SSL server.

#### Machine 3

This machine acts as a regular client.
Run config examples (args needed):

args: ```<userAlias> <password> <newDevice(0-false or 1-true)> <deviceName> <account>```
- Alice account: `alice alice_iphone 1 iphone alice`
- Bob account: `bob bob_iphone 1 iphone bob`
- Alice accessing Alice and Bob's shared account: `alice alice_iphone 1 iphone alice_bob`

## Demonstration

Now that all the networks and machines are up and running, lets execute the application. You can check what is happening in the Server <-> DataBase after SSL handshake.

```sh
From: DataBase, To: DataBase
Message: Starting database server...
```

```sh
From: Server, To: Server
Message: Starting Server...
```

```sh
From: Server, To: Server
Message: Connecting to DataBase Server...
```

After the SSL handshake, Server needs to send his Certificate and the HMAC of it to the DataBase.
```sh
From: Server, To: DataBase
Message: Received the Certificate from Server: [
[
  Version: V3
  Subject: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
  Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11

  Key:  Sun RSA public key, 2048 bits
  params: null
  modulus: 25779561905750510373419739059923559439627324708376322507804615103656903684569011864142545713836950421022896468440624800814235386749694890437106289350239420807056843598248641935271009646711475698826139649251736500847597861476501688109619588444329015038214742466499696343219011900786134810491528012291032559463539862529050448481783377694412041041072373390793364908581421164275756518358247663142330564168137475770981865610115204366077708321885742174381614555072097086988198379586260131691795591933940553824396324788464997566125132257782538476376089969164708118951553811166150270067683299226459913072568510259882294581757
  public exponent: 65537
  Validity: [From: Sun Dec 10 16:14:43 WET 2023,
               To: Sat Mar 09 16:14:43 WET 2024]
  Issuer: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
  SerialNumber: [    20beb20c c77b51d4]

Certificate Extensions: 1
[1]: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 42 13 9F DA BD 59 1C E6   CC 00 F7 76 81 A2 7A 2B  B....Y.....v..z+
0010: 4F DE B8 48                                        O..H
]
]

]
  Algorithm: [SHA256withRSA]
  Signature:
0000: C8 54 95 93 D2 9D 7F 73   6C 75 F8 63 FC CC 98 9C  .T.....slu.c....
0010: 5D BE 3A A0 00 07 BA 38   72 33 C4 C4 20 30 36 50  ].:....8r3.. 06P
0020: AE 8F E3 D9 2D A2 95 AD   A9 0A 5E 99 1B CE 76 CA  ....-.....^...v.
0030: 0C 8B B3 A4 00 10 62 2B   99 5D B4 CD EA 1B 20 C8  ......b+.].... .
0040: 99 23 AD 56 E1 FE AA 92   DA E3 32 08 37 03 2B 03  .#.V......2.7.+.
0050: 81 45 22 D4 3A 7E 5D 19   79 E9 F2 6A CA 7D F1 F8  .E".:.].y..j....
0060: 53 E9 E7 6A 3F 25 CA 64   93 D3 68 8D 04 80 A2 38  S..j?%.d..h....8
0070: D0 2F CE 2E EC 19 AE D0   C4 77 EC 40 70 A0 A3 CB  ./.......w.@p...
0080: 70 18 6C 59 2C E8 F6 50   C4 7B D0 99 2B 6A FF 10  p.lY,..P....+j..
0090: 50 57 25 43 CF 28 35 CE   7F 6B F4 43 52 18 22 F1  PW%C.(5..k.CR.".
00A0: B5 58 AE F2 EF D7 24 31   76 D5 48 F7 9A 9D 50 3A  .X....$1v.H...P:
00B0: E8 5E EB 1E E4 C0 62 8A   B8 53 D9 9C EB F3 33 3F  .^....b..S....3?
00C0: 0B 78 11 8A 0A 55 D0 2C   5B 10 5E CE 0C BC D2 09  .x...U.,[.^.....
00D0: BA 6D 54 49 7D D2 27 98   36 BF 8B A6 BA 82 22 A2  .mTI..'.6.....".
00E0: F1 B1 75 13 0D 68 4D 38   E3 89 AD F9 01 9D 31 57  ..u..hM8......1W
00F0: 69 8A 21 1B 55 5C A4 57   82 1B 1B 77 5A 39 0D 0E  i.!.U\.W...wZ9..

]
```

```sh
From: Server, To: DataBase
Message: Received the HMAC of the Certificate from Server: [B@7231b9f9
```

```sh
From: DataBase, To: DataBase
Message: Verifying the integrity of the Server Certificate.
```

```sh
From: DataBase, To: DataBase
Message: Comparing the Server Certificate in DataBase TrustStore with the received one...
```

```sh
From: DataBase, To: Server
Message: (Authentic Certificate.) EncryptedAllCorrectFlag: d/kqusBXPfwT1b57fOTCPjBJ0ULKg2K0ZarH+6hJQrI=|KQRcSu31uwc0uJAAHqyu1hEINC5bPL6RFZsYK7xu5a4uzKYblxruCUlGp7Nw43wdiqRGNPmV0/+/UV2mK5yq/Wn9E8Ulv5BTJux9F+o0owucZsNvJ6Kpx99YIQy8vN3zDmIO1JQgqV1oLnWzebWYT++D+4jprh/x+BYuwc1qt3ZVe0GXWorG0IOZuwLEdxC+AALG0p8CvMTGvDxCHvfSv845nsFDnhtA2jC1mfF4HGQz2RcCrW9Kwo2whSdMTnMKh8vKBYArlsodg84qtbWdmUTXIiK07wG6X6ma61ac1njmrEKiHbQx0M3bIdtgJSxozpyZNUhUZh8ftNw3iMYQxg==
```

Now that the connection is in fact established, lets access Alice's account.
<br>(Run config: `alice alice_iphone 1 iphone alice`)<br>
Since the new device flag is active, the application will execute some additional tasks, we can check that in the Client output:
```sh
Starting client...
RSA & keystore generated successfully.
Certificate added to the truststore successfully.
```
 - And a similiar Certificate exchange process will happen (not showing again since it is the same process as shown before).

--------------------------------------------------
Now let's explore the features of the application.
```sh
Welcome alice!
Here you have the list of commands you can execute:
 - In order to see your balance, write the following command > balance
 - In order to see your movements, write the following command > movements
 - In order to make a movement, write the following command adding the value and the description > make_movement <value> <description>
 - In order to make a payment, write the following command adding the value, destiny account (alias name) and description make_payment > make_payment <value> <destinyAccount> <description>
 - In order to see your payments, write the following command > payments
 - In order to see your pending payments, write the following command > payments_to_confirm
 - In order to confirm your pending payments, write the following command > confirm_payment <Payment ID>
```

Let's check Alice's balance:
```sh
$ balance
```

The server should respond with:

```sh
$ Your balance is: 872.22
```

Checking the log file we see that the message transmitted from the client to the server was:

```sh
From: Client, To: Server
Message: EncryptedPayload: fKk+jG3lraXuA6GWLg1+517dnhXCMyEDCa4uE4/5j94=|DRwae2HGZZ/gMHi4oTaVnunl01wNGEE7rn1CHMCTL+ZBlai4d5oM9Pn5rHyBvA2jtAFDyDiBzP0m69vpXkUd+uw066Dg/RfuYyfareDWWHsz6lmSgxgDOeBghDhowXatgOajDzi57y5Kmqo9xOzoqJB10k1Ohe/cx1TjN0vT0e0w1w0upqbGzpHqYzhXgcNDAs0U5VKP/4n0sXd5xIxxqtDCjXPbQPR1WBKKq/mgIn9DdtQI6vXiggu6XXjxIAA0KwpzPISIqBbjAnxrx+bL5qHGUBjfDehG89pmlf0HTS9SvnpIGi4thjgiwmWhwsHW+AURHN56kJj97n8Q0DScaQ==
DecryptedPayload: balance
```

And the server response was:

```sh
From: Server, To: Client
Message: EncryptedPayload: 7rCQnkoaoDuG6BlMX+0/pTDumg5AhUt9hgL0jSlk8ZY67ENhxEz9LV2LKdWThFMG|G13jlub9upcvkzZ3cLC0wKmH5MC0iztm9uzPEpFk8u/0Kllgzheb8JbifpXopeB748zsHwgIc3126gBA+Nv1hTq/hAKMMq4ddSg2y5U7Zp7+aU5o6DkOt5W9FLiJT/d/CfJRUzJJALEAyo3Gm5JxbBcnWuEO13ZutFmdXL4WgdNGNWikN5jpJXZxh87m1rkd+FzOnIj2k++kJPYQa4AR1DGi8v731vBbChgF2U7Rtn/i0a/W2w1mzQW9uyez+rRVTc0q8jeGNtsrEg37hWzoyt/jQB/AVd0CmX3nZg+Vwh95eHGogvrwAMSn9ao2Y3cCy6daZTlgyz2rbbFS33ZrFQ==
DecryptedPayload: Your balance is: 872.22
```

We can further verify that the information was transmitted from the database to the server as follows:

```shell
From: DataBase, To: Server
Message: EncryptedAccount: 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
DecryptedAccount: {"accountHolder":["alice"],"balance":872.22,"currency":"EUR","movements":[{"date":"09/11/2023","value":1000.00,"description":"Salary"},{"date":"15/11/2023","value":-77.78,"description":"Electricity bill"},{"date":"22/11/2023","value":-50.00,"description":"ATM Withdrawal"}]}
```
--------------------------------------------------
Let's check Alice's movements:
```sh
$ movements
```

The server should respond with:

```sh
Date: 09/11/2023
Value: 1000.0
Description: Salary

Movement
Date: 15/11/2023
Value: -77.78
Description: Electricity bill

Movement
Date: 22/11/2023
Value: -50.0
Description: ATM Withdrawal
```

Checking the log file we see that the message transmitted from the client to the server was:

```sh
From: Client, To: Server
Message: EncryptedPayload: /JNqTi+ND57+XUM7wvFj3QyFV/T9Zf02XTbRK2/CxyI=|JioKxxkV9rDF5FbTf+A0ZeJdfD6jlrCOMkcQrjkCp3nCN768Bau/6GfRQiagl1AtL9myQQdeyYhnsQSz1B+WFhVOM/IgH1wReK3eWYgwXh5CQN4Fe8mKVLEsCMTCm6kdagf1HuQpcNR9YC+trwI6VfTyUTRKjQQtHHxI2Rp53jxeb8tdllLCz2r4HzC2SWgG04wkMqqyfscfR+Yl2wwT1pU3U3u4ixr8UP++ZuyeGcvgTkcyObfd9iExjx4y4J6vorw0xdt3A9T00Bn61zR2Wyb9B1Wn2N1yy3Roj9Az/gP5y4L9Rw2/HvubIcQTg3ov5YFvESMeqM+y2EiPvMnluQ==
DecryptedPayload: movements
```

And the server response was:

```sh
From: Server, To: Client
Message: resultMovements: ViY3YEdX6NitbWr0X22ZuPrOKMc4NgmH8v7AdGrrUOZF3UDv4h2R/0kEQmFsEroWQanveu5bD0dcICv/C4ZGt4sJ+WpXieFGx13Vy5fSuzk39Iw/fRS4tD6oFPY0RXs3m36p1yYSiwYg56qVywwkfrQKUeacA5aBdCpQCorwNM0Sx8cZQwtpWSzK6bsu5e9usahj+sGr4EWKzhPAtxAiuuD5oeHd6Br4UAIuL6ZzXJ3+Zj9iNRTEquyTucsjv0+VPDLo5USJLL1ek0prLcJYvDKWngbTZOXCyqxdbRchvHo=|MGe3vessMnIsXMeyD6Gi2jkLeiyCs4uL8qXOSgGnGVlo9iII+yU+EPS6YwXMNBSbHnxA6GMN4xizMebGieOQuCQVK/4ylS14so9tVJH6e626JbeNEkj0Co1D7bRAv34va7RLQ60HzT3iGsCxpi7Cd/J0TS/xJELIPM8QYu8z2wf8oLTQQGGeAOqBfRnf71a3ZFegz/w/8itmoZy5NvHM3p3HrLORfyNLX3aICWiZPom9ZLc+Ti235JlnlG1vC8hyAdhHLSWdIbCBwt8K/gpnXszMZzyWAO8f43YBkQtCs93rW/0cih9QOtwRKezfy3SnoibsTPWPd7QxrZTNw3ppag==
```

We can further verify that the information was transmitted from the database to the server as follows:

```shell
From: Database, To: Server
Message: 
Account File: rO0ABXNyABNkdG8uU2lnbmVkT2JqZWN0RFRPAAAAAAAAAAACAAJMAAtjZXJ0aWZpY2F0ZXQAIExqYXZhL3NlY3VyaXR5L2NlcnQvQ2VydGlmaWNhdGU7TAAMc2lnbmVkT2JqZWN0dAAcTGphdmEvc2VjdXJpdHkvU2lnbmVkT2JqZWN0O3hwcHNyABpqYXZhLnNlY3VyaXR5LlNpZ25lZE9iamVjdAn/vWgqPNX/AgADWwAHY29udGVudHQAAltCWwAJc2lnbmF0dXJlcQB+AAVMAAx0aGVhbGdvcml0aG10ABJMamF2YS9sYW5nL1N0cmluZzt4cHVyAAJbQqzzF/gGCFTgAgAAeHAAAAR6rO0ABXNyABVkdG8uU2VjdXJlRG9jdW1lbnREVE8AAAAAAAAAAAIAAkwACGRvY3VtZW50dAASTGphdmEvbGFuZy9TdHJpbmc7TAAJdGltZXN0YW1wdAAQTGphdmEvbGFuZy9Mb25nO3hwdAPAc0pXbHNtUi9CaDd2L1dqeml6YVpiV1pSUUhVdGJRYXJiT3kwcSs5VExJTmxEYjVidTMrTWRJSmxjOUpDNnlqZjFHdmJvT3QvcUR4T3F0TUVxSW1LbHdUWEU5eTNrUHdjVWlxL0FJQkdJVVZQY0lWMmhMUzFuZXM5YmZKQlpTNEtEby9iVjg5ZStCSTFQc3ptTXBLVFIrNEN1V2c2c013VjhnbWsvZmdpVFY5bnFLOER6OVl2dTAyRUQ0MGtpdDBKbG54NXFQaU9JbE1KTTRGZE5kOC9iZGVUYi81WXA0OEcrUTh6V2ppamZ1ZDhZOUkxY2JxQU16UUdOU0E1bDI0NWtETTBhR3ZXOWVPUGVValpCRkN4VUx2amE3bnJXSXZMbTdWR0FFWmtaczE5VEVoQU9TK292b2JyajZ2MzZDVG1aOFQ5TXUrcytnVE9MZ2oxUW55OFd1YVVneGxvdlNEa3o3OHVLL0ZtSnlkMFFjemVlMkRWWmp2ZDB3U3UvQ3dzekIwMzloOWFPT3BZU2diOTlOTmlhUVdFMDlFY0ZFa2JvbE1MUE15YUcxZU1RazgrUVcyM21hRUdOb0E4Y01uWk9Ja1c1b3VnaWlUTDA1VGQzM3VVR1ZBSCswSk4rdW15S2MzSFQ4b1lpSHpVSEgwNHVUQlFJcTZLVitLblltNHJ5TFpCdTRaM0lteitmbzdWQURCRjRkSW9jQndHZDRmamE4RWtCRTFQZ250NjN2ZXJuTnh4dlJSU0RtVUNDNXVrck1oNXJyRkFpRFpqZkVPZzJYK3Q1R3lpREk2Q2R5ZUJCVVpON2kvWVptSmlrWSt6VE4rSm5jRm1HMmhoOXpESGRRWDVvQ2dXOGszdUdvWm9jdFNBa2xRbTd2aitRa0tIc3REUmgweDBMNDZPZGR6YVAzRWZwL0k2TGxzVkNNaXFDa3lFZ0hjMWJKZFI3ckJTQ3Ayc2F5dFpjVjhPMjdIVzk3L0xKTVkyS0p0RWMxRVV3N29zNjlMaU5USTBRdXBlejZSVHZYZGZhL0o2ZVJJRzR3VWVkY3FQcGRPUVBqeXNjMS9tR3d2b3VrU3g5Q29YTzd3WHJ3QUh1Y2VyOHlnS2h5UmRoaXJtMjFRd2lOa210SUZsMXJSb2QwZGF0MnFXdHk4R3hhRnp6TCtSclBsUE4yS3RLcmtaNUorT3BTZUFUMU05L2t6S1c0UGJZanA2ZUtYS0R5cTl5b2xtT2JIRlN1SnB6M0E3REhDdzN6UUc0WmVYWHo5bWUxRW9Zektvc3IADmphdmEubGFuZy5Mb25nO4vkkMyPI98CAAFKAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAYyLyQCldXEAfgAIAAABABVIKALJtsQej0d749txUgvZrhdEwKOroLD4s3fMy79lwH8suLMLu3YyJD14ycgOwzdkLaw5JbqxqOuYkm2b4BMXdBLNEx8I5lLgrlYRRyRmOJtfPQS1r77RKw9917xr4diQYcr/2NtrukWwTXurP7QEyCW38wGRZslUMjwTD1ow8NQ0grUdmrze/Svc8+xgAJnymocSjo2Y3v7nxcN1hbKt2EQHMg7R2j/wBhTRTAQRWe5nKUhI+3F1TN0CBhJsbOPqbU8habxUpcq5QXtrrkRnIQk2DzR/HLFjs+Tk98r82/VQb433Ni6vyAay7N0r/OpcKCrG+wqZHgquQBUcgcR0AA1TSEEyNTZ3aXRoUlNB
```
--------------------------------------------------
Let's make a movement:
```sh
$ make_movement 50 Water bill
```

The server should respond with:

```sh
Movement done!
```

Checking the log file we see that the message transmitted from the client to the server was:

```sh
From: Client, To: Server
Message: EncryptedPayload: F5UxBgwa4sLdshtwIZJQuCKg/KfgIZWOTau1/0K51pclNIAr7ai6A4c9yiQ40BI9v3LvEPUrTyilZdum+TNbZA==|FXxqQFS2WhEMrWDM3tehDhXWGfdRdPg4/1xvKWatL4rPgc8mHMl2PHfmuyKNU5EzuUzYDMQ1illfJvO+qeUz5ct7xSKkOG5BVCS2kErnwIOzynlKqH/UH/kWdBU5jRb0rQmVIuJOQNkXsjRTVL9v14uXlxoG7iQR3LuqoO51jHJP7dZokarOmt2oHhA1ZWu67U4OyFZgxaJvIr9bHVmfGq52ryuMn9iy7DeoftyEKlj/wnSLq8rKRKMr41jcjuQXXOuL1uarnieWjWCmn5RywYk8/cd4/26SeqxI3xtCzCq0sPrtvvnoNxTgeWMgzo9bQ9arfkrqeOAv8phJRG/Pkw==
DecryptedPayload: make_movement 50 Electricity bill
```

And the server response was:

```sh
From: Server, To: Client
Message: ResultMakeMovement: 2cvWoulLTZV2RVyDhzrmakCt1LaJrQssTkd5wrDO8EQ=|qh73sFLvg65NwBKZfbNDO9hk1mIu0JNL9JHrdw9hPigbd8klsM1mOWNDEQnZixVp58Ef2xKB+OxaqPLpl3boJ79RiaehtrAxNflHeeThRcMocZkdloDsSjFKlmNKvu7VyFdMOv+NBPy1ltNRIfMMP7jFGQwY72qYAqCwaBwYmaMsGn98SZkjwflJ3kEQ+liTmw01uPD9Snt3BNnU+F54kd28MERRDm/0/5deI2NodDuHGbI85Ep39apyQEgK8Lgi8VPh6gePiJChHL7lL4tY9TakcnjShKIyBKuerHcgu9fCiCCShecPQxku8ghFV99T3O79gRg1X42P2qB1W+2A6g==
```

We can further verify that the information was transmitted from the Server to the Database as follows:
<br>Server sends the new updated balance encrypted with the two layer option encryption, such that the DataBase after his decryption still cannot check the plain value of the balance attribute.
```shell
From: Server, To: Database
Message: 
EncryptedUpdatedBalance: CgthFnmCtT8COwT5Qjpv3svg4Fm9ZQ1yn8cpcPasyCLhr0keOR1sTu9ts7gki37X57zvurfB2JtMTCTv4uWmpwSLk1oogEx7NZO/pbDr2LC6ON8UbhfV77PiBfSqVH61aUFx7KTW8XvM+O7FR1vN5Q==|t4bO+2fF2ukayM66pR770cRgyBRpddllbG/XHKlDskTiELPulbMEiHUW62ylMZNFOi8VgFIlJy7pi8iJv1pk8QZIYjh6RmY1UD21j6CEeh2W5f01wQUreCG4BRktYL0PA+r/6gPFJmnYAmVsW5Gd3b2DQZkXEwCMh/v5DUjUsQ3V5caB7woHVpsistqks47VRpb2TbM+6SBx343BoBk0Tper7FTNve8oC+QCabcn/7BQaw7beJDnU8WFO7jwHNK9EmVa4BSXaTv/cTE1o1acJSNuQBhO6smTh9ROjkwdngliYl+uHuOyLGlPsoQuwLUw0PhwGR9iThuAl5EFKOQnYQ==
DecryptedUpdatedBalance: RDKk2Hu6I+OeBCYFVpmSFxEhimJMzFNWopDFLPoGfds=
```
Down here we can check the Server sending to DataBase the new movement in order to add it to the account file. Again, note the importance of the two layer encryption.
```shell
From: Server, To: Database
Message:
EncryptedValuesMovement2Layer: acWuPO0r9SCY5l3GWoMnP/S0hC6ohZm96XXSaRLyRla1qt8JKlcFQBz92aLtVnnsa+1oNKF0KG3xJfzfQb4LXTpRWD21A0N4nQInrPfxBOkJ8Fo+gZJmK0FW7YZ5eesqZNvnTzOEaJGum8zQgIyLzH9I4xulcFb1zv+ZMdowjA50Mp8aPyMXyLpuMNx/dTEClpgPuSfphE6fj4Tz0++jmwagPbkYzvwni44FI55kkL6fVlNep8pOWGXAIMc1jyMJpv1sFKVqCihHnjvEHDQuVaqX5WjfepU2SaNxcZwmBVoWB4e+Rhuvy73IeD9V7kYfffTu1kjwbhK8W1NP1hcL/+dr1SpCuatIZIoAGhdyz/rj0adKcdbt99OIEUnUcMBDyC4m0nf9AewACX9LN3GBCA==|wEcVWUk/FpkVPWC87gz5ilAIN+ZUfMlpzQ+WgNkg5BOnYUBRVIWDjHtrUoR5ZsyPlC393bF+qIyGPaa/nJ/Rd/AwvmOIIexr/uNHJV3nHaE0zBaThlABauZOJXO2cDVxsbUbH1WUpZUL0LaxoqDcskOKrs9m/bj91ulxnqE0eY2fhugd1R654JXF7Tu+JFzXlWV4D5E0PAzX4hUUsUzw2VbcBSazt7oc8wod3mS8m6UrnQ8MFAWj0R2NGaEYXexM8ykSrg1wy6wtq1cJtHLuTB0DDfV8ihkkzLpcQxJvHOpt9WTRY0rdd5q8DXHn1bAIipU7Q7erOk50Cul2lvXGAQ==
EncryptedValuesMovement1Layer: {"encryptedValue":"G5azVyBJIPR/cFJrQGgFVw==","encryptedDate":"Ss9skX4cugImy9M7gMOkSADcpU2vnLJwW2MyUghI8Cs=","encryptedDescription":"7wWDqpcmqU3Hmt6U8B8oCFcrqsmtJIqPzUxgBjjgwQ0="}
```
And the confirmation from DataBase.
```shell
From: Database, To: Server
Message:
MovementStatusDecrypted: Movement done!
MovementStatusEncrypted:x3St9HFMnohb+0sn88bedpUAD05vow/4sAh6jqMaeGE=|ojnX7NwrlrS6Z3+4npiEoREWrVW9zJNWGzRPBL3DBmUUFoN/YeUmkU5h5yqZKTgqIuEn+kia/VSFxLD6VaNUtHW2p4PxCGAWErPA0OwCIdYS2etdySZEImVZ+CE9wkAcng5uIWwMam1jf+e4htKrQvFbKRU9ijeMxytp3qE7GRf3nCbR8s8Rwx6ZPeumD4IhfmDbKZVNhE5YsBopSCYSMheczxDkHVA6eOvb1vxqegercL+XWDBeXjq+BogBKX83eojFhj5O5AUpwW4VQuqwFZvBpQxjvLvWpv9h84O++VvYW6a1ExJmrxtBY+iNA5/FPBVSo8kIK8vp0AMOTKh9tg==
```
--------------------------------------------------
We can check the new updated balance and the new added movement by executing the commands balance and movements, respectively:
```sh
$ balance
Your balance is: 822.22
```
```sh
$ movements

Date: 09/11/2023
Value: 1000.0
Description: Salary

Movement
Date: 15/11/2023
Value: -77.78
Description: Electricity bill

Movement
Date: 22/11/2023
Value: -50.0
Description: ATM Withdrawal

Movement
Date: 21/12/2023
Value: -50.0
Description: Water bill
```
--------------------------------------------------
Now, for testing the payments feature let's connect Alice to Alice and Bob's shared account.
<br>Run config: `alice alice_iphone 1 iphone alice_bob`


This concludes the demonstration.

## Additional Information

### Links to Used Tools and Libraries

- [Java 11.0.16.1](https://openjdk.java.net/)
- [Maven 3.9.5](https://maven.apache.org/)
- ...

### Versioning

We use [SemVer](http://semver.org/) for versioning.  

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

*(switch to another license, or no license, as you see fit)*

----
END OF README
