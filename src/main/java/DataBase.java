import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;

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

        MongoDatabase mongoDB = connectToMongoDB("url de conexao", "nome da bd");

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
                DataBaseThread dbt = new DataBaseThread(socket, mongoDB);
                dbt.start();
            }
           } catch (Exception e1) {
            System.out.println("Error when initializing database");
            }
    }

    public static MongoDatabase connectToMongoDB(String connectionString, String databaseName) {
        try (MongoClient mongoClient = MongoClients.create(connectionString)) {
            return mongoClient.getDatabase(databaseName);
        } catch (Exception e) {
            System.err.println("Erro ao conectar ao MongoDB: " + e.getMessage());
            return null;
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
    private final MongoDatabase mongodb;

    public DataBaseThread(SSLSocket inSoc, MongoDatabase mongoDB) {
        this.socket = inSoc;
        this.mongodb = mongoDB;
    }

    @Override
    public void run() {
        System.setProperty("javax.net.debug", "ssl");


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
                in.close();
                out.close();
                System.exit(1);
            }

            //Compare the Server Certificate in DataBase TrustStore with the received one
            KeyStore dataBaseTS = KeyStore.getInstance("PKCS12");
            dataBaseTS.load(new FileInputStream(new File(trustStorePath)), trustStorePass.toCharArray());
            Certificate serverCertificateFromDBTrustStore = dataBaseTS.getCertificate("servercert");

            if(!serverCertificateReceived.equals(serverCertificateFromDBTrustStore)) {
                System.out.println("Non-authentic Certificate.");
                in.close();
                out.close();
                System.exit(1);
            }

            //actions
            while(true) {
                
            }

        } catch (Exception e) {
            e.printStackTrace();
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