import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import dto.SignedObjectDTO;
import org.bson.Document;

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

            //actions
                while(true) {
                    String decryptedUpdateFlag = secureMessageLibServer.unprotectMessage(in.readUTF());
                    String decryptedAccount = secureMessageLibServer.unprotectMessage(in.readUTF());

                    if(!decryptedUpdateFlag.equals("Error verifying signature") && !decryptedUpdateFlag.equals("Decryption Failed")
                            && !decryptedAccount.equals("Decryption Failed") && !decryptedAccount.equals("Error verifying signature") && userAccountCollection != null) {
                        String[] clientsFromAccount = decryptedAccount.split("_");
                        if(decryptedUpdateFlag.equals("0")) {
                            if(clientsFromAccount.length > 1) { // TODO
                                //buscar conta partilhada
                                // ir buscar conta que tem todos os clientsFromAccount associado

                                // fazer protect com flag a 0

                                // pegar nos bytes do ficheiro

                                //enviar bytes do ficheiro

                                //apagar

                            } else {
                                getAccount(userAccountCollection, secureDocumentLib, secureMessageLibServer, out, clientsFromAccount);
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
                                        JsonObject encryptedValuesMovement = secureDocumentLib.decryptMovement(secureMessageLibServer.unprotectMessage(in.readUTF()));

                                        // Query to find the document where accountHolder is exactly equal to clientsFromAccount array
                                        Document query = new Document("accountHolder", new Document("$all", Arrays.asList(clientsFromAccount)));

                                        // Execute the query and get the first matching document
                                        Document matchingDocument = userAccountCollection.find(query).first();

                                        Document novoMovimentoDocument = Document.parse(encryptedValuesMovement.toString());

                                        Document update = new Document("$push", Collections.singletonMap("account.movements", novoMovimentoDocument));

                                        // Executar a atualização
                                        userAccountCollection.updateOne(query, update);

                                        out.writeUTF(secureMessageLibServer.protectMessage("Movement done!"));
                                    }
                                    //update db adicionando o novo movement enviar resposta se correu bem ou nao encriptada com secureMessageLib
                                    break;


                            }
                        }
                    } else {
                        out.writeUTF(secureMessageLibServer.protectMessage("An error in decryption ocurred"));
                    }
                }

        } catch (Exception e) {
            e.printStackTrace();
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
            SignedObjectDTO protectedData = secureDocumentLib.protect(jsonObjectReceived,"",false);

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
                "DataBase/initDataBase/plain_text/alcides_account.json"};

        String[] encFilePaths = new String[]{"DataBase/initDataBase/enc_text/alice_account_enc.bin",
                "DataBase/initDataBase/enc_text/bob_account_enc.bin",
                "DataBase/initDataBase/enc_text/mario_account_enc.bin",
                "DataBase/initDataBase/enc_text/alcides_account_enc.bin"};

        String[] resultDecFilePaths = new String[]{"DataBase/initDataBase/unprotect_result/alice_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/bob_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/mario_account_unprotected.json",
                "DataBase/initDataBase/unprotect_result/alcides_account_unprotected.json"};

        String[] accountAliasArray = new String[]{"alice", "bob", "mario", "alcides"};

        //Just for init - We use the Server KeyStore to protect the files
        SecureDocumentLib secureDocumentLib = new SecureDocumentLib("serverKeyStore", "serverKeyStore", "Server/serverKeyStore/serverKeyStore");

        for (int i = 0; i < plainFilePaths.length; i++) {
            Gson gson = new Gson();
            try (FileReader plainFileReader = new FileReader(plainFilePaths[i])){
                JsonObject plainFile = gson.fromJson(plainFileReader, JsonObject.class);
                writeToFile(new File(encFilePaths[i]), secureDocumentLib.protect(plainFile, accountAliasArray[i], true));

                ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(encFilePaths[i]));
                SignedObjectDTO encFile = (SignedObjectDTO) objectInputStream.readObject();
                writeToFile(new File(resultDecFilePaths[i]), secureDocumentLib.unprotect(encFile, accountAliasArray[i], false));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


            MongoCollection<Document> userAccountCollection = mongoDB.getCollection("userAccount");
            userAccountCollection.drop();

            for (int i = 0; i < resultDecFilePaths.length; i++) {
                File currentDecryptedFile = new File(resultDecFilePaths[i]);

                // Read the content of the JSON file
                String jsonContent = null;
                try {
                    jsonContent = new String(Files.readAllBytes(currentDecryptedFile.toPath()));
                } catch (IOException e) {
                    System.err.println("Error while getting file");
                }

                // Parse the JSON content to a MongoDB Document
                Document document = Document.parse(jsonContent);

                // Insert the document into the "userAccount" collection
                userAccountCollection.insertOne(document);

                System.out.println("Document inserted successfully!");
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

