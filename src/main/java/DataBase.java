import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import dto.SignedObjectDTO;
import org.bson.Document;
import com.mongodb.client.result.UpdateResult;
import java.nio.file.Files;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Objects;

import static utils.utils.writeToFile;

public class DataBase {

    private static final int port = 54321;

    private static final String keyStoreName = "dataBaseKeyStore";
    private static final String keyStorePass = "dataBaseKeyStore";
    private static final String keyStorePath = "DataBase//dataBaseKeyStore//" + keyStoreName;

    private static final String privateKeyAlias = "pk";

    private static final String trustStoreName = "dataBaseTrustStore";
    private static final String trustStorePass = "dataBaseTrustStore";
    private static final String trustStorePath = "DataBase//dataBaseKeyStore//" + trustStoreName;

    private static final String connectionString = "mongodb+srv://grupo09SIRS:FWcnIQ39qyytoBWH@blingbank.a3q9851.mongodb.net/?retryWrites=true&w=majority";

    private static final String databaseName = "BlingBank";


    public static void main(String[] args) {
        System.out.println("Starting database server...");

        // setup keystore
        File keyStore = new File(keyStorePath);

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        // create socket
        ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();

        try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port)) {
            MongoClient mongoClient = MongoClients.create(connectionString);
            MongoDatabase mongoDB = mongoClient.getDatabase(databaseName);
            while(true) {
                SSLSocket socket = (SSLSocket) ss.accept();
                DataBaseThread dbt = new DataBaseThread(socket, mongoDB);
                dbt.start();
            }
           } catch (Exception e1) {
            System.out.println("Error when initializing database");
            }
    }
}

class DataBaseThread extends Thread {

    private static final String keyStoreName = "dataBaseKeyStore";
    private static final String keyStorePass = "dataBaseKeyStore";
    private static final String keyStorePath = "DataBase//dataBaseKeyStore//" + keyStoreName;

    private static final String trustStoreName = "dataBaseTrustStore";
    private static final String trustStorePass = "dataBaseTrustStore";
    private static final String trustStorePath = "DataBase//dataBaseKeyStore//" + trustStoreName;

    private final SSLSocket socket;
    private final MongoDatabase mongoDB;

    public DataBaseThread(SSLSocket inSoc, MongoDatabase mongoDB) {
        this.socket = inSoc;
        this.mongoDB = mongoDB;
    }

    @Override
    public void run() {

        System.out.println("Server connecting to DataBase");

        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String secretKeyAlias = "server_db_secret";
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                KeyStore dbKeyStore = KeyStore.getInstance("PKCS12");
                dbKeyStore.load(fis, keyStorePass.toCharArray());

                // Check if the alias is present in the keystore
                if (!dbKeyStore.containsAlias(secretKeyAlias)) {
                    System.out.println("Alias '" + secretKeyAlias + "' is not present in the keystore.");

                    // Load another keystore (replace this with your actual logic)
                    String serverKeyStorePath = "Server//serverKeyStore//serverKeyStore";
                    String serverKeyStorePassword = "serverKeyStore";

                    try (FileInputStream serverFis = new FileInputStream(serverKeyStorePath)) {
                        KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
                        serverKeyStore.load(serverFis, serverKeyStorePassword.toCharArray());

                        // Check if the alias is present in the other keystore
                        System.out.println("Alias '" + secretKeyAlias + "' is present in the other keystore.");

                        // Alias exists, you can retrieve the symmetric key
                        SecretKey secretKey = (SecretKey) serverKeyStore.getKey(secretKeyAlias, serverKeyStorePassword.toCharArray());
                        // Use the key as needed
                        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
                        dbKeyStore.setEntry(secretKeyAlias, skEntry, new KeyStore.PasswordProtection(keyStorePass.toCharArray()));

                        try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
                            dbKeyStore.store(fos, keyStorePass.toCharArray());
                        }
                    }
                }
            }

            //Receive and verify the integrity of the Server Certificate
            //Receive the Certificate from Server
            Certificate serverCertificateReceived = (Certificate) in.readObject();
            byte[] serverCertificateHMAC = (byte[]) in.readObject();

            //Get SecretKey associated to Server
            KeyStore dataBaseKS = KeyStore.getInstance("PKCS12");
            dataBaseKS.load(new FileInputStream(new File(keyStorePath)), keyStorePass.toCharArray());
            SecretKey secretKey = (SecretKey) dataBaseKS.getKey("server_db_secret", keyStorePass.toCharArray());

            if(!verifyHMac(secretKey, serverCertificateReceived, serverCertificateHMAC)) {
                System.out.println("Corrupted Certificate. HMAC verification failed.");
                //Error flag.
                out.writeUTF("0");
                in.close();
                out.close();
                System.exit(1);
            }

            //Compare the Server Certificate in DataBase TrustStore with the received one
            KeyStore dataBaseTS = KeyStore.getInstance("PKCS12");
            dataBaseTS.load(new FileInputStream(new File(trustStorePath)), trustStorePass.toCharArray());
            Certificate serverCertificateFromDBTrustStore = dataBaseTS.getCertificate("serverrsa");

            if(!serverCertificateReceived.equals(serverCertificateFromDBTrustStore)) {
                System.out.println("Non-authentic Certificate.");
                //Error flag.
                out.writeUTF("0");
                in.close();
                out.close();
                System.exit(1);
            }

            //Verifiy if first time (Empty DataBase)
            //if()


            //Send a confirmation flag > 0-Error; 1-Correct
            //All correct flag
            out.writeUTF("1");
            out.flush();

            initDataBase(mongoDB);

            SecureMessageLib secureMessageLibServer = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath,
                    "server_db", "databasersa", "serverrsa");

            SecureDocumentLib secureDocumentLib = new SecureDocumentLib(keyStoreName, keyStorePass, keyStorePath);


            MongoCollection<Document> userAccountCollection = null;
            userAccountCollection = mongoDB.getCollection("userAccount");

            MongoCollection<Document> userPaymentCollection = null;
            userPaymentCollection = mongoDB.getCollection("userAccountPayments");

            //actions
                while(true) {
                    String decryptedUpdateFlag = secureMessageLibServer.unprotectMessage(in.readUTF());
                    String decryptedAccount = secureMessageLibServer.unprotectMessage(in.readUTF());

                    if(!decryptedUpdateFlag.equals("Error verifying signature") && !decryptedUpdateFlag.equals("Decryption Failed")
                            && !decryptedAccount.equals("Decryption Failed") && !decryptedAccount.equals("Error verifying signature") && userAccountCollection != null) {
                        String[] clientsFromAccount = decryptedAccount.split("_");
                        if(decryptedUpdateFlag.equals("0")) {
                            String docType = secureMessageLibServer.unprotectMessage(in.readUTF());
                            if(docType.equals("account")){
                                getAccount(userAccountCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);
                            } else {
                                getAccountPayment(userPaymentCollection,secureDocumentLib,secureMessageLibServer, out, clientsFromAccount);
                            }


                            // Update db
                        } else {
                            String request = secureMessageLibServer.unprotectMessage(in.readUTF());
                            //tratar dos pedidos de update
                            String [] requestSplit = request.split(" ");
                            getAccount(userAccountCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);

                            switch (requestSplit[0]) {
                                case "movement":
                                    if(secureMessageLibServer.unprotectMessage(in.readUTF()).equals("ok")){
                                        String updatedBalance = secureDocumentLib.decryptBalance(secureMessageLibServer.unprotectMessage(in.readUTF()));
                                        //String updatedBalance = secureMessageLibServer.unprotectMessage(in.readUTF());

                                        Document filterToAccount = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

                                        Document updateBalance = new Document("$set", new Document("encryptedBalance", updatedBalance));
                                        UpdateResult updateBalanceResult = userAccountCollection.updateOne(filterToAccount, updateBalance);

                                        if (updateBalanceResult.getModifiedCount() > 0) {
                                            System.out.println("Balance updated successfully");
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                            break;
                                        }

                                        JsonObject encryptedValuesMovement = secureDocumentLib.decryptMovement(secureMessageLibServer.unprotectMessage(in.readUTF()));
                                        Document novoMovimentoDocument = Document.parse(encryptedValuesMovement.toString());
                                        // Create an update to push the new values to the "movements" array
                                        Document updateMovement = new Document("$push", new Document("movements", novoMovimentoDocument));
                                        UpdateResult updateMovementResult = userAccountCollection.updateOne(filterToAccount, updateMovement);

                                        if (updateMovementResult.getModifiedCount() > 0) {
                                            out.writeUTF(secureMessageLibServer.protectMessage("Movement done!"));
                                            out.flush();
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                        }
                                    }
                                    //update db adicionando o novo movement enviar resposta se correu bem ou nao encriptada com secureMessageLib
                                    break;

                                case "payment":
                                    if(secureMessageLibServer.unprotectMessage(in.readUTF()).equals("ok")) {
                                        getAccountPayment(userPaymentCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);

                                        String updatedBalance = secureDocumentLib.decryptBalance(secureMessageLibServer.unprotectMessage(in.readUTF()));

                                        Document filterToAccount = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

                                        Document updateBalance = new Document("$set", new Document("encryptedBalance", updatedBalance));
                                        UpdateResult updateBalanceResult = userAccountCollection.updateOne(filterToAccount, updateBalance);

                                        if (updateBalanceResult.getModifiedCount() > 0) {
                                            System.out.println("Balance updated successfully");
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                            break;
                                        }

                                        JsonObject encryptedValuesPayment = secureDocumentLib.decryptPayment(secureMessageLibServer.unprotectMessage(in.readUTF()));
                                        Document newPaymentDocument = Document.parse(encryptedValuesPayment.toString());
                                        // Create an update to push the new values to the "movements" array
                                        Document updatePayment = new Document("$push", new Document("payments", newPaymentDocument));
                                        UpdateResult updatePaymentResult = userPaymentCollection.updateOne(filterToAccount, updatePayment);

                                        if (updatePaymentResult.getModifiedCount() > 0) {
                                            out.writeUTF(secureMessageLibServer.protectMessage("Payment done!"));
                                            out.flush();
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                        }
                                    }
                                    break;

                            }
                        }
                    } else {
                        out.writeUTF(secureMessageLibServer.protectMessage("An error in decryption ocurred"));
                        out.flush();
                    }
                }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void getAccountPayment(MongoCollection<Document> userAccountPaymentCollection, SecureDocumentLib secureDocumentLib, SecureMessageLib secureMessageLibServer, ObjectOutputStream out, String[] clientsFromAccount) {
        //buscar conta singular
        // Query to find the document where accountHolder is exactly equal to clientsFromAccount array
        Document query = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

        // Execute the query and get the first matching document
        Document matchingDocument = userAccountPaymentCollection.find(query).first();

        if (matchingDocument != null) {
            // Store the Document in a JSON file

            JsonObject jsonObjectReceived = documentToJsonObject(matchingDocument);
            SignedObjectDTO protectedData = secureDocumentLib.protect(jsonObjectReceived,"",false, "payment");

            String result = null;
            try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(protectedData);
                byte[] serializedObject = bos.toByteArray();
                result = Base64.getEncoder().encodeToString(serializedObject);
                out.writeUTF(secureMessageLibServer.protectMessage(Objects.requireNonNullElse(result, "An error in decryption ocurred")));
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No matching document found.");
        }
    }

    private void getAccount(MongoCollection<Document> userAccountCollection, SecureDocumentLib secureDocumentLib, SecureMessageLib secureMessageLibServer, ObjectOutputStream out, String[] clientsFromAccount) {
        //buscar conta singular
        // Query to find the document where accountHolder is exactly equal to clientsFromAccount array
        Document query = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

        // Execute the query and get the first matching document
        Document matchingDocument = userAccountCollection.find(query).first();

        if (matchingDocument != null) {
            // Store the Document in a JSON file

            JsonObject jsonObjectReceived = documentToJsonObject(matchingDocument);
            SignedObjectDTO protectedData = secureDocumentLib.protect(jsonObjectReceived,"",false, "account");

            String result = null;
            try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(protectedData);
                byte[] serializedObject = bos.toByteArray();
                result = Base64.getEncoder().encodeToString(serializedObject);
                out.writeUTF(secureMessageLibServer.protectMessage(Objects.requireNonNullElse(result, "An error in decryption ocurred")));
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No matching document found.");
        }
    }


    //We are using the PrivateKey of the Server just to INIT the DB. Not supposed to be like this.
    private void initDataBase(MongoDatabase mongoDB) {

        String[] plainFilePaths = new String[]{"DataBase/initDataBase/plain_text/alice_account.json",
                "DataBase/initDataBase/plain_text/bob_account.json",
                "DataBase/initDataBase/plain_text/mario_account.json",
                "DataBase/initDataBase/plain_text/alcides_account.json",
                "DataBase/initDataBase/plain_text/alice_bob_account.json"};

        String[] plainPaymentsFilePaths = new String[]{"DataBase/initDataBase/plain_text/alice_account_payments.json",
                "DataBase/initDataBase/plain_text/bob_account_payments.json",
                "DataBase/initDataBase/plain_text/mario_account_payments.json",
                "DataBase/initDataBase/plain_text/alcides_account_payments.json",
                "DataBase/initDataBase/plain_text/alice_bob_account_payments.json"};


        String[] encFilePaths = new String[]{"DataBase/initDataBase/enc_text/alice_account_enc.bin",
                "DataBase/initDataBase/enc_text/bob_account_enc.bin",
                "DataBase/initDataBase/enc_text/mario_account_enc.bin",
                "DataBase/initDataBase/enc_text/alcides_account_enc.bin",
                "DataBase/initDataBase/enc_text/alice_bob_account_enc.bin"};

        String[] encPaymentsFilePaths = new String[]{"DataBase/initDataBase/enc_text/alice_account_payments_enc.bin",
                "DataBase/initDataBase/enc_text/bob_account_payments_enc.bin",
                "DataBase/initDataBase/enc_text/mario_account_payments_enc.bin",
                "DataBase/initDataBase/enc_text/alcides_account_payments_enc.bin",
                "DataBase/initDataBase/enc_text/alice_bob_account_payments_enc.bin"};


        String[] resultDecFilePaths = new String[]{"DataBase/initDataBase/unprotect_result/alice_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/bob_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/mario_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/alcides_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/alice_bob_account_unprotected.json"};

        String[] resultDecPaymentsFilePaths = new String[]{"DataBase/initDataBase/unprotect_result/alice_account_payments_unprotected.json",
                "DataBase/initDataBase/unprotect_result/bob_account_payments_unprotected.json",
                "DataBase/initDataBase/unprotect_result/mario_account_payments_unprotected.json",
                "DataBase/initDataBase/unprotect_result/alcides_account_payments_unprotected.json",
                "DataBase/initDataBase/unprotect_result/alice_bob_account_payments_unprotected.json"};

        String[] accountAliasArray = new String[]{"alice", "bob", "mario", "alcides", "alice_bob"};

        //Just for init - We use the Server KeyStore to protect the files
        SecureDocumentLib secureDocumentLib = new SecureDocumentLib("serverKeyStore", "serverKeyStore", "Server/serverKeyStore/serverKeyStore");

        for (int i = 0; i < plainFilePaths.length; i++) {
            Gson gson = new Gson();
            try (FileReader plainFileReader = new FileReader(plainFilePaths[i]);
                 FileReader plainPaymentsFileReader = new FileReader(plainPaymentsFilePaths[i])){

                JsonObject plainFile = gson.fromJson(plainFileReader, JsonObject.class);
                writeToFile(new File(encFilePaths[i]), secureDocumentLib.protect(plainFile, accountAliasArray[i], true, "account"));

                ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(encFilePaths[i]));
                SignedObjectDTO encFile = (SignedObjectDTO) objectInputStream.readObject();
                writeToFile(new File(resultDecFilePaths[i]), secureDocumentLib.unprotect(encFile, accountAliasArray[i], false, "account"));

                //AGAIN, BUT FOR PAYMENTS - TEM DE SE ADAPTAR O PROTECT E UNPROTECT PARA ESTES FICHEIROS!!!
                JsonObject plainPaymentsFile = gson.fromJson(plainPaymentsFileReader, JsonObject.class);
                writeToFile(new File(encPaymentsFilePaths[i]), secureDocumentLib.protect(plainPaymentsFile, accountAliasArray[i], true, "payment"));

                ObjectInputStream objectInputStreamPayments = new ObjectInputStream(new FileInputStream(encPaymentsFilePaths[i]));
                SignedObjectDTO encPaymentsFile = (SignedObjectDTO) objectInputStreamPayments.readObject();
                writeToFile(new File(resultDecPaymentsFilePaths[i]), secureDocumentLib.unprotect(encPaymentsFile, accountAliasArray[i], false, "payment"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


            MongoCollection<Document> userAccountCollection = mongoDB.getCollection("userAccount");
            userAccountCollection.drop();

            MongoCollection<Document> userAccountPaymentsCollection = mongoDB.getCollection("userAccountPayments");
            userAccountPaymentsCollection.drop();

            for (int i = 0; i < resultDecFilePaths.length; i++) {
                File currentDecryptedFile = new File(resultDecFilePaths[i]);
                File currentDecryptedPaymentsFile = new File(resultDecPaymentsFilePaths[i]);

                // Read the content of the JSON file
                String jsonContent = null;
                String jsonPaymentsContent= null;
                try {
                    jsonContent = new String(Files.readAllBytes(currentDecryptedFile.toPath()));
                    jsonPaymentsContent = new String(Files.readAllBytes(currentDecryptedPaymentsFile.toPath()));
                } catch (IOException e) {
                    System.err.println("Error while getting file");
                }

                // Parse the JSON content to a MongoDB Document
                Document document = Document.parse(jsonContent);
                Document paymentsDocument = Document.parse(jsonPaymentsContent);

                // Insert the document into the "userAccount" collection
                userAccountCollection.insertOne(document);
                userAccountPaymentsCollection.insertOne(paymentsDocument);

                System.out.println("Documents inserted successfully!");
            }


    }
    public static boolean verifyHMac(SecretKey secretKey, Certificate certificate, byte[] receivedHMac) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        // Calculate the expected HMAC using the received certificate
        byte[] expectedHMac = mac.doFinal(certificate.getEncoded());

        // Compare the calculated HMAC with the received HMAC
        return MessageDigest.isEqual(expectedHMac, receivedHMac);
    }

    private JsonObject documentToJsonObject(Document matchingDocument) {
            String jsonString = matchingDocument.toJson();
            Gson gson = new Gson();
            return gson.fromJson(jsonString, JsonObject.class);
    }
}

