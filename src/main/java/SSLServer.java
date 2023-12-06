import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SSLServer {

    private static final int port = 12345;

    private static final String keyStoreName = "serverKeyStore";
    private static final String keyStorePass = "serverKeyStore";
    private static final String keyStorePath = "keyStore//" + keyStoreName;

    private static final String privateKeyAlias = "pk";

    private static final String trustStoreName = "serverTrustStore";
    private static final String trustStorePass = "serverTrustStore";
    private static final String trustStorePath = "trustStore//" + trustStoreName;

    public static void main(String[] args) throws Exception {
        System.out.println("Starting server...");

        // setup keystore
        SSLContext sc = SSLContext.getInstance("TLS");
        File keyStore = new File(keyStorePath);

        if(!keyStore.exists()) {
            try {
                // Generate a key pair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                // Create a KeyStore and store the key pair in it
                KeyStore ks = KeyStore.getInstance("PKCS12");
                char[] password = keyStorePass.toCharArray();
                ks.load(null, password);

                // Generate a self-signed X.509 certificate
                X509Certificate selfSignedCert = generateSelfSignedCertificate(keyPair);

                KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{selfSignedCert});
                ks.setEntry(privateKeyAlias, privateKeyEntry, new KeyStore.PasswordProtection(password));

                // Save the KeyStore to a file
                try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
                    ks.store(fos, password);
                }
            } catch (Exception e) {
                System.out.println("Error creating the KeyStore");
            }
        }

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        // setup truststore
        File trustStore = new File(trustStorePath);

        if(!trustStore.exists()) {
            try {
                // Create a TrustStore
                KeyStore ts = KeyStore.getInstance("PKCS12");
                char[] password = trustStorePass.toCharArray();
                ts.load(null, password);

                // Save the TrustStore to a file
                try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
                    ts.store(fos, password);
                }
            } catch (Exception e) {
                System.out.println("Error creating the TrustStore");
            }
        }

        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

        // create socket
        SSLServerSocket serverSocket = null;
        try {
            serverSocket = (SSLServerSocket) sc.getServerSocketFactory().createServerSocket(port);
        } catch (Exception e1) {
            System.out.println("Error when initializing server");
        }

        if(serverSocket != null) {
            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                ServerThread st = new ServerThread(socket);
                st.start();
            }
        }
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        // Get the current date
        Date startDate = new Date();

        // Set the validity period of the certificate (e.g., 365 days)
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000);

        // Generate a self-signed X.509 certificate
        X509Certificate cert = null;
        try {
            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
            X500Principal subjectName = new X500Principal("CN=Self-Signed Certificate");

            certGenerator.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            certGenerator.setSubjectDN(subjectName);
            certGenerator.setIssuerDN(subjectName);
            certGenerator.setNotBefore(startDate);
            certGenerator.setNotAfter(endDate);
            certGenerator.setPublicKey(keyPair.getPublic());
            certGenerator.setSignatureAlgorithm("SHA256withRSA");

            cert = certGenerator.generate(keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cert;
    }
}

class ServerThread extends Thread {

    private final SSLSocket socket;

    public ServerThread(SSLSocket inSoc) {
        this.socket = inSoc;
    }

    @Override
    public void run() {

        System.out.println("Client connected");

        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

        } catch (Exception e) {
            System.out.println("Client disconnected");
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                System.out.println("An error occurred in communication");
            }
        }
    }
}