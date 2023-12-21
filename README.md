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

Now that all the networks and machines are up and running, try to check your balance on the `Alice` client:

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
