import javax.crypto.Mac;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SSLServer {

    private static final int port = 12345;

    private static final String keyStoreName = "serverKeyStore";
    private static final String keyStorePass = "serverKeyStore";
    private static final String keyStorePath = "Server//serverKeyStore//" + keyStoreName;

    private static final String privateKeyAlias = "pk";

    private static final String trustStoreName = "serverTrustStore";
    private static final String trustStorePass = "serverTrustStore";
    private static final String trustStorePath = "Server//serverKeyStore//" + trustStoreName;

    public static void main(String[] args) {

        System.out.println("Starting server...");

        // setup keystore
        File keyStore = new File(keyStorePath);

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);


        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

        // create socket
        ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();

        try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port)) {
            while (true) {
                SSLSocket socket = (SSLSocket) ss.accept();
                ServerThread st = new ServerThread(socket);
                st.start();
            }
        } catch (Exception e1) {
            System.out.println("Error when initializing server");
        }
    }
}

class ServerThread extends Thread {

    private static final String keyStoreName = "serverKeyStore";
    private static final String keyStorePass = "serverKeyStore";
    private static final String keyStorePath = "Server//serverKeyStore//" + keyStoreName;

    private static final String trustStoreName = "serverTrustStore";
    private static final String trustStorePass = "serverTrustStore";
    private static final String trustStorePath = "Server//serverKeyStore//" + trustStoreName;

    private final SSLSocket socket;
    private SSLSocket dataBaseSocket;

    public ServerThread(SSLSocket inSoc) {
        this.socket = inSoc;
    }

    @Override
    public void run() {

        System.out.println("Client connected");

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

        System.setProperty("javax.net.debug", "ssl");

        // connect to database
        SocketFactory sf = SSLSocketFactory.getDefault();
        try {
            dataBaseSocket = (SSLSocket) sf.createSocket("localhost", 54321);
            System.out.println("Depois DE Ligação, port:54321");
            ObjectOutputStream out = new ObjectOutputStream(dataBaseSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(dataBaseSocket.getInputStream());

            //Send the Certificate (with HMAC) from Server to DB
            String serverRSAAlias = "serverrsa";
            KeyStore serverKS = KeyStore.getInstance("PKCS12");
            serverKS.load(new FileInputStream(new File(keyStorePath)), keyStorePass.toCharArray());

            Certificate serverCertificate = serverKS.getCertificate(serverRSAAlias);
            SecretKey secretKey = (SecretKey) serverKS.getKey("server_db_secret", keyStorePass.toCharArray());

            //send the certificate and the associated HMAC
            out.writeObject(serverCertificate);
            out.writeObject(calculateHMac(secretKey, serverCertificate));
            out.flush();

        } catch (Exception e) {
            e.printStackTrace();
            try {
                dataBaseSocket.close();
            } catch (IOException ex) {
                System.out.println("DataBase connection closed");
            }
        }

        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String clientIdentifier = in.readUTF();
            //userAlias + "_" + deviceName + "true(newDevice) or false(!newDevice)"
            String[] clientIdentifierSplitted = clientIdentifier.split(" ");
            String userAndDevice = clientIdentifierSplitted[0];

            //2args == newDevice flag
            if(clientIdentifierSplitted.length == 2){
                Certificate clientCertificate = (Certificate) in.readObject();
                byte[] clientCertificateHMAC = (byte[]) in.readObject();

                //Get SecretKey associated to current client
                KeyStore serverKS = KeyStore.getInstance("PKCS12");
                serverKS.load(new FileInputStream(new File(keyStorePath)), keyStorePass.toCharArray());
                SecretKey secretKey = (SecretKey) serverKS.getKey(userAndDevice + "_secret", keyStorePass.toCharArray());


                //Compromise HMAC Test - uncomment to test it.
                // Concatenate the byte array of character 'a' to clientCertificateHMAC
                /*byte[] testBytes = "a".getBytes(StandardCharsets.UTF_8);
                clientCertificateHMAC = Arrays.copyOf(clientCertificateHMAC, clientCertificateHMAC.length + testBytes.length);
                System.arraycopy(testBytes, 0, clientCertificateHMAC, clientCertificateHMAC.length - testBytes.length, testBytes.length);*/

                if(!verifyHMac(secretKey, clientCertificate, clientCertificateHMAC)) {
                    System.out.println("Corrupted Certificate. HMAC verification failed.");
                    in.close();
                    out.close();
                    System.exit(1);
                }

                //Load the TrustStore and add the certificate if not exists yet
                KeyStore serverTS = KeyStore.getInstance("PKCS12");
                serverTS.load(new FileInputStream(new File(trustStorePath)), trustStorePass.toCharArray());
                serverTS.setCertificateEntry(userAndDevice + "_cert", clientCertificate);

                FileOutputStream fos = null;
                try {
                    fos = new FileOutputStream(trustStorePath);
                    serverTS.store(fos, trustStorePass.toCharArray());
                } finally {
                    if (fos != null) {
                        fos.close();
                    }
                }
            }

            //actions
            while(true) {
            }

        } catch (Exception e) {
            System.out.println("Client disconnected");
            try {
                socket.close();
            } catch (IOException ex) {
                System.out.println("Socket closed");
            }
        }
    }

    public static byte[] calculateHMac(SecretKey secretKey, Certificate certificate) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(certificate.getEncoded());
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