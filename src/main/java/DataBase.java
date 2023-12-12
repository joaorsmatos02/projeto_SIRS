import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import java.nio.file.Files;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;

public class DataBase {

    private static final int port = 54321;

    private static final String keyStoreName = "dataBaseKeyStore";
    private static final String keyStorePass = "dataBaseKeyStore";
    private static final String keyStorePath = "DataBase//dataBaseKeyStore//" + keyStoreName;

    private static final String privateKeyAlias = "pk";

    private static final String trustStoreName = "dataBaseTrustStore";
    private static final String trustStorePass = "dataBaseTrustStore";
    private static final String trustStorePath = "DataBase//dataBaseKeyStore//" + trustStoreName;


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
            while(true) {
                SSLSocket socket = (SSLSocket) ss.accept();
                DataBaseThread dbt = new DataBaseThread(socket);
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
    private static final String connectionString = "mongodb+srv://grupo09SIRS:FWcnIQ39qyytoBWH@blingbank.a3q9851.mongodb.net/?retryWrites=true&w=majority";
    private static final String databaseName = "BlingBank";

    public DataBaseThread(SSLSocket inSoc) {
        this.socket = inSoc;
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

            //Send a confirmation flag > 0-Error; 1-Correct
            //All correct flag
            out.writeUTF("1");

            //Verifiy if first time (Empty DataBase)
            //if()
            initDataBase();

            //actions
            while(true) {
                
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    //We are using the PrivateKey of the Server just to INIT the DB. Not supposed to be like this.
    private void initDataBase() {

        String[] plainFilePaths = new String[]{"DataBase/initDataBase/plain_text/alice_account.json",
                                               "DataBase/initDataBase/plain_text/bob_account.json",
                                               "DataBase/initDataBase/plain_text/mario_account.json",
                                               "DataBase/initDataBase/plain_text/alcides_account.json"};

        String[] encFilePaths = new String[]{"DataBase/initDataBase/enc_text/alice_account_enc.bin",
                                             "DataBase/initDataBase/enc_text/bob_account_enc.bin",
                                             "DataBase/initDataBase/enc_text/mario_account_enc.bin",
                                             "DataBase/initDataBase/enc_text/alcides_account_enc.bin"};

        String[] accountAliasArray = new String[]{"alice", "bob", "mario", "alcides"};

        for (int i = 0; i < plainFilePaths.length; i++) {
            //falta flag
            SecureDocumentLib.protect(new File(plainFilePaths[i]), new File(encFilePaths[i]), accountAliasArray[i]);
        }

        for (int i = 0; i < plainFilePaths.length; i++) {
            try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(new File(encFilePaths[0])))) {

            } catch (Exception e) {

                e.printStackTrace();
            }
        }


        //Just for test
        try (MongoClient mongoClient = MongoClients.create(connectionString)) {
            MongoDatabase mongoDB = mongoClient.getDatabase(databaseName);

            File testFile = new File("DataBase/initDataBase/plain_text/alice_account.json");

            MongoCollection<Document> userAccountCollection = mongoDB.getCollection("userAccount");

            // Read the content of the JSON file
            String jsonContent = new String(Files.readAllBytes(testFile.toPath()));

            // Parse the JSON content to a MongoDB Document
            Document document = Document.parse(jsonContent);

            // Insert the document into the "userAccount" collection
            userAccountCollection.insertOne(document);

            System.out.println("Document inserted successfully!");
        } catch (IOException e) {
            System.err.println("MongoDB connection error: " + e.getMessage());
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
}