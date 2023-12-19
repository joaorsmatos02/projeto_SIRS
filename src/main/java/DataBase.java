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
import static utils.utils.writeLogFile;

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
        writeLogFile("DataBase", "DataBase", "Starting database server...");

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
            writeLogFile("DataBase", "DataBase", "Starting connection...");

            while(true) {
                SSLSocket socket = (SSLSocket) ss.accept();
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                DataBaseThread dbt = new DataBaseThread(mongoDB, out, in);
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


    private final MongoDatabase mongoDB;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;

    public DataBaseThread(MongoDatabase mongoDB, ObjectOutputStream out, ObjectInputStream in) {
        this.mongoDB = mongoDB;
        this.out = out;
        this.in = in;
    }

    @Override
    public void run() {

        try{
            writeLogFile("DataBase", "DataBase", "Server connected");
            SecureMessageLib secureMessageLibServer = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath,
                    "server_db", "databasersa", "serverrsa");

            SecureDocumentLib secureDocumentLib = new SecureDocumentLib(keyStoreName, keyStorePass, keyStorePath);

            String secretKeyAlias = "server_db_secret";
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                KeyStore dbKeyStore = KeyStore.getInstance("PKCS12");
                dbKeyStore.load(fis, keyStorePass.toCharArray());

                // Check if the alias is present in the keystore
                if (!dbKeyStore.containsAlias(secretKeyAlias)) {
                    writeLogFile("DataBase", "DataBase", "Check if Secret Key between Server and DB is present in the DB keystore - FALSE");
                    System.out.println("Alias '" + secretKeyAlias + "' is not present in the keystore.");

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
                            writeLogFile("DataBase", "DataBase", "Secret Key between Server and DB added in the DB keystore.");
                        }
                    }
                }
            }

            //Receive and verify the integrity of the Server Certificate
            //Receive the Certificate from Server
            Certificate serverCertificateReceived = (Certificate) in.readObject();
            writeLogFile("Server", "DataBase", "Receive the Certificate from Server: " + serverCertificateReceived.toString());
            byte[] serverCertificateHMAC = (byte[]) in.readObject();
            writeLogFile("Server", "DataBase", "Receive the HMAC of the Certificate from Server: " + serverCertificateHMAC.toString());

            //Get SecretKey associated to Server
            KeyStore dataBaseKS = KeyStore.getInstance("PKCS12");
            dataBaseKS.load(new FileInputStream(new File(keyStorePath)), keyStorePass.toCharArray());
            SecretKey secretKey = (SecretKey) dataBaseKS.getKey("server_db_secret", keyStorePass.toCharArray());

            if(!verifyHMac(secretKey, serverCertificateReceived, serverCertificateHMAC)) {
                System.out.println("Corrupted Certificate. HMAC verification failed.");
                //Error flag.
                String encryptedErrorFlag = secureMessageLibServer.protectMessage("0");
                out.writeUTF(encryptedErrorFlag);
                writeLogFile("DataBase", "Server", "(Corrupted Certificate. HMAC verification failed.) EncryptedErrorFlag: " + encryptedErrorFlag);
                in.close();
                out.close();
                System.exit(1);
            }
            writeLogFile("DataBase", "DataBase", "HMAC of the Server Certificate verified successfully");

            //Compare the Server Certificate in DataBase TrustStore with the received one
            KeyStore dataBaseTS = KeyStore.getInstance("PKCS12");
            dataBaseTS.load(new FileInputStream(new File(trustStorePath)), trustStorePass.toCharArray());
            Certificate serverCertificateFromDBTrustStore = dataBaseTS.getCertificate("serverrsa");

            writeLogFile("DataBase", "DataBase", "Comparing the Server Certificate in DataBase TrustStore with the received one...");
            if(!serverCertificateReceived.equals(serverCertificateFromDBTrustStore)) {
                System.out.println("Non-authentic Certificate.");
                //Error flag.
                String encryptedErrorFlag = secureMessageLibServer.protectMessage("0");
                out.writeUTF(encryptedErrorFlag);
                writeLogFile("DataBase", "Server", "(Non-authentic Certificate.) EncryptedErrorFlag: " + encryptedErrorFlag);
                in.close();
                out.close();
                System.exit(1);
            }

            //Send a confirmation flag > 0-Error; 1-Correct
            //All correct flag
            String encryptedAllCorrectFlag = secureMessageLibServer.protectMessage("1");
            writeLogFile("DataBase", "Server", "(Authentic Certificate.) EncryptedAllCorrectFlag: " + encryptedAllCorrectFlag);
            out.writeUTF(encryptedAllCorrectFlag);
            out.flush();

            initDataBase(mongoDB);


            MongoCollection<Document> userAccountCollection = null;
            userAccountCollection = mongoDB.getCollection("userAccount");

            MongoCollection<Document> userPaymentCollection = null;
            userPaymentCollection = mongoDB.getCollection("userAccountPayments");


                //actions
                writeLogFile("DataBase", "Database", "Waiting for actions...");
                while(true) {
                    String encryptedUpdateFlag = in.readUTF();
                    String decryptedUpdateFlag = secureMessageLibServer.unprotectMessage(encryptedUpdateFlag);
                    String encryptedAccount = in.readUTF();
                    String decryptedAccount = secureMessageLibServer.unprotectMessage(encryptedAccount);
                    writeLogFile("Server", "Database", "\nEncryptedUpdateFlag: " + encryptedUpdateFlag + "\nDecryptedUpdateFlag: " + decryptedUpdateFlag +
                                                                        "\nEncryptedAccount: " + encryptedAccount + "\nDecryptedAccount: " + decryptedAccount);

                    if(!decryptedUpdateFlag.equals("Error verifying signature") && !decryptedUpdateFlag.equals("Decryption Failed")
                            && !decryptedAccount.equals("Decryption Failed") && !decryptedAccount.equals("Error verifying signature") && userAccountCollection != null) {
                        String[] clientsFromAccount = decryptedAccount.split("_");
                        if(decryptedUpdateFlag.equals("0")) {
                            String encryptedDocType = in.readUTF();
                            String docType = secureMessageLibServer.unprotectMessage(encryptedDocType);
                            writeLogFile("Server", "Database", "\nEncryptedDocType: " + encryptedDocType +
                                    "\nDecryptedDocType: " + docType);

                            if(docType.equals("account")){
                                getAccount(userAccountCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);
                            } else {
                                getAccountPayment(userPaymentCollection,secureDocumentLib,secureMessageLibServer, out, clientsFromAccount);
                            }

                        // Update db
                        } else {
                            String encryptedRequest = in.readUTF();
                            String request = secureMessageLibServer.unprotectMessage(encryptedRequest);
                            writeLogFile("Server", "Database", "\nEncryptedRequest: " + encryptedRequest +
                                    "\nDecryptedRequest" + request);

                            //tratar dos pedidos de update
                            String [] requestSplit = request.split(" ");
                            getAccount(userAccountCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);

                            switch (requestSplit[0]) {
                                case "movement":
                                    String encryptedConfirmationFlag = in.readUTF();
                                    String decryptedConfirmationFlag = secureMessageLibServer.unprotectMessage(encryptedConfirmationFlag);
                                    writeLogFile("Server", "Database", "(Movement)\nEncryptedConfirmationFlag: " + encryptedConfirmationFlag +
                                            "\nDecryptedConfirmationFlag" + decryptedConfirmationFlag);

                                    if(decryptedConfirmationFlag.equals("ok")){
                                        String encryptedUpdatedBalance = in.readUTF();
                                        String updatedBalance = secureDocumentLib.decryptBalance(secureMessageLibServer.unprotectMessage(encryptedUpdatedBalance));
                                        writeLogFile("Server", "Database", "\nEncryptedUpdatedBalance: " + encryptedUpdatedBalance +
                                                "\nDecryptedUpdatedBalance" + updatedBalance);

                                        Document filterToAccount = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

                                        Document updateBalance = new Document("$set", new Document("encryptedBalance", updatedBalance));
                                        UpdateResult updateBalanceResult = userAccountCollection.updateOne(filterToAccount, updateBalance);

                                        if (updateBalanceResult.getModifiedCount() > 0) {
                                            System.out.println("Balance updated successfully");
                                            writeLogFile("DataBase", "Database", "Balance updated successfully");
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                            writeLogFile("DataBase", "Database", "Error while performing movement.");
                                            break;
                                        }

                                        String encryptedValuesMovementString = in.readUTF();
                                        JsonObject encryptedValuesMovement = secureDocumentLib.decryptMovement(secureMessageLibServer.unprotectMessage(encryptedValuesMovementString));
                                        writeLogFile("Server", "Database", "\nEncryptedValuesMovement2Layer: " + encryptedValuesMovementString +
                                                          "\nEncryptedValuesMovement1Layer: " + encryptedValuesMovement.toString());

                                        Document novoMovimentoDocument = Document.parse(encryptedValuesMovement.toString());
                                        // Create an update to push the new values to the "movements" array
                                        Document updateMovement = new Document("$push", new Document("movements", novoMovimentoDocument));
                                        UpdateResult updateMovementResult = userAccountCollection.updateOne(filterToAccount, updateMovement);

                                        if (updateMovementResult.getModifiedCount() > 0) {
                                            String movementStatusEncrypted = secureMessageLibServer.protectMessage("Movement done!");
                                            out.writeUTF(movementStatusEncrypted);
                                            out.flush();
                                            writeLogFile("Database", "Server", "\nMovementStatusDecrypted: Movement done!\n" +
                                                                "MovementStatusEncrypted:" + movementStatusEncrypted);
                                        } else {
                                            String movementStatusEncrypted = secureMessageLibServer.protectMessage("Error while performing movement.");
                                            out.writeUTF(movementStatusEncrypted);
                                            writeLogFile("Database", "Server", "\nMovementStatusDecrypted: Error while performing movement.\n" +
                                                    "MovementStatusEncrypted:" + movementStatusEncrypted);
                                        }
                                    }
                                    break;

                                case "payment":
                                    String encryptedConfirmationFlagPayment = in.readUTF();
                                    String decryptedConfirmationFlagPayment = secureMessageLibServer.unprotectMessage(encryptedConfirmationFlagPayment);
                                    writeLogFile("Server", "Database", "(Payment)\nEncryptedConfirmationFlag: " + encryptedConfirmationFlagPayment +
                                            "\nDecryptedConfirmationFlag: " + decryptedConfirmationFlagPayment);

                                    if(decryptedConfirmationFlagPayment.equals("ok")) {
                                        getAccountPayment(userPaymentCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);

                                        String encryptedUpdatedBBalance = in.readUTF();
                                        String updatedBalance = secureDocumentLib.decryptBalance(secureMessageLibServer.unprotectMessage(encryptedUpdatedBBalance));
                                        writeLogFile("Server", "Database", "\nNewEncryptedBalance: " + encryptedUpdatedBBalance +
                                                "\nNewDecryptedBalance: " + updatedBalance);

                                        Document filterToAccount = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

                                        Document updateBalance = new Document("$set", new Document("encryptedBalance", updatedBalance));
                                        UpdateResult updateBalanceResult = userAccountCollection.updateOne(filterToAccount, updateBalance);

                                        if (updateBalanceResult.getModifiedCount() > 0) {
                                            System.out.println("Balance updated successfully");
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                            break;
                                        }

                                        String encryptedUpdatedPaymentNumber = in.readUTF();
                                        String updatedPaymentNumber = secureDocumentLib.decryptPaymentNumber(secureMessageLibServer.unprotectMessage(encryptedUpdatedPaymentNumber));
                                        Document filterToAccountPayment = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));
                                        writeLogFile("Server", "Database", "\nEncryptedUpdatedPaymentNumber: " + encryptedUpdatedPaymentNumber +
                                                "\nDecryptedUpdatedPaymentNumber: " + updatedPaymentNumber);

                                        Document updatePayNumber = new Document("$set", new Document("encryptedPaymentNumbers", updatedPaymentNumber));
                                        UpdateResult updatePaymentNumberResult = userPaymentCollection.updateOne(filterToAccountPayment, updatePayNumber);

                                        if (updatePaymentNumberResult.getModifiedCount() > 0) {
                                            System.out.println("Payment Number updated successfully");
                                        } else {
                                            out.writeUTF("Error while performing movement.");
                                            break;
                                        }

                                        String encryptedValuesPayment2Layer = in.readUTF();
                                        JsonObject encryptedValuesPayment = secureDocumentLib.decryptPayment(secureMessageLibServer.unprotectMessage(encryptedValuesPayment2Layer));
                                        writeLogFile("Server", "Database", "\nEncryptedValuesPayment2Layer: " + encryptedValuesPayment2Layer +
                                                "\nEncryptedValuesPayment1Layer: " + encryptedValuesPayment.toString());

                                        Document newPaymentDocument = Document.parse(encryptedValuesPayment.toString());
                                        // Create an update to push the new values to the "movements" array
                                        Document updatePayment = new Document("$push", new Document("payments", newPaymentDocument));
                                        UpdateResult updatePaymentResult = userPaymentCollection.updateOne(filterToAccount, updatePayment);

                                        if (updatePaymentResult.getModifiedCount() > 0) {
                                            String encryptedUpdatePaymentResult = secureMessageLibServer.protectMessage("Payment done!");
                                            out.writeUTF(encryptedUpdatePaymentResult);
                                            out.flush();
                                            writeLogFile("DataBase", "Server", "\nDecryptedUpdatePaymentResult: Payment done!" +
                                                    "\nEncryptedUpdatePaymentResult: " + encryptedUpdatePaymentResult);
                                        } else {
                                            String encryptedUpdatePaymentResult = secureMessageLibServer.protectMessage("Error while performing movement.");
                                            out.writeUTF(encryptedUpdatePaymentResult);
                                            writeLogFile("DataBase", "Server", "\nDecryptedUpdatePaymentResult: Error while performing movement." +
                                                    "\nEncryptedUpdatePaymentResult: " + encryptedUpdatePaymentResult);
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
        writeLogFile("Database", "Database", "Payment option - Get Payment File associated to the account query.");

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
                writeLogFile("Database", "Server", "\nPayment Account File: " + result);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No matching document found.");
        }
    }

    private void getAccount(MongoCollection<Document> userAccountCollection, SecureDocumentLib secureDocumentLib, SecureMessageLib secureMessageLibServer, ObjectOutputStream out, String[] clientsFromAccount) {
        //Get singular account
        // Query to find the document where accountHolder is exactly equal to clientsFromAccount array
        Document query = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

        // Execute the query and get the first matching document
        writeLogFile("Database", "Database", "Account option - Get account query.");
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
                writeLogFile("Database", "Server", "\nAccount File: " + result);
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
        writeLogFile("DataBase", "Database", "DataBase init successfully");
    }
    public static boolean verifyHMac(SecretKey secretKey, Certificate certificate, byte[] receivedHMac) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        // Calculate the expected HMAC using the received certificate
        byte[] expectedHMac = mac.doFinal(certificate.getEncoded());

        // Compare the calculated HMAC with the received HMAC
        writeLogFile("DataBase", "DataBase", "Verifying the integrity of the Server Certificate.");
        return MessageDigest.isEqual(expectedHMac, receivedHMac);
    }

    private JsonObject documentToJsonObject(Document matchingDocument) {
            String jsonString = matchingDocument.toJson();
            Gson gson = new Gson();
            return gson.fromJson(jsonString, JsonObject.class);
    }
}

