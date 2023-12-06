import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Client {

    public static void main(String[] args) throws Exception {

        if (args.length != 4) {
            System.out.println("Wrong args. help command.");
            //help command
        }

        System.out.println("Starting client...");

        //args: 0-userAlias | 1-password | 2-newDevice(0-false or 1-true)| 3-deviceName
        String userAlias = args[0];
        String passwordStores = args[1];
        boolean newDevice = "1".equals(args[2]);
        String deviceName = args[3];

        String keyStoreName = userAlias + "_" + deviceName + "_KeyStore";
        String keyStorePath = userAlias + "_" + deviceName + "_" + "keyStore//" + keyStoreName;

        String privateKeyAlias = "pk";

        String trustStoreName = userAlias + "_" + deviceName + "_TrustStore";
        String trustStorePath = userAlias + "_" + deviceName + "_trustStore//" + trustStoreName;

        // setup keystore
        File keyStore = new File(keyStorePath);

        if (!keyStore.exists() && newDevice) {
            try {
                new File(userAlias + "_" + deviceName + "_" + "keyStore").mkdir();
                // Generate a key pair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                // Create a KeyStore and store the key pair in it
                KeyStore ks = KeyStore.getInstance("PKCS12");
                char[] passwordKeyStoreChar = passwordStores.toCharArray();
                ks.load(null, passwordKeyStoreChar);

                // Generate a self-signed X.509 certificate
                X509Certificate selfSignedCert = generateSelfSignedCertificate(keyPair);

                KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{selfSignedCert});
                ks.setEntry(privateKeyAlias, privateKeyEntry, new KeyStore.PasswordProtection(passwordKeyStoreChar));

                // Save the KeyStore to a file
                try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
                    ks.store(fos, passwordKeyStoreChar);
                }
            } catch (Exception e) {
                System.out.println("Error creating the KeyStore");
            }
        }

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", passwordStores);

        // setup truststore
        File trustStore = new File(trustStorePath);

        if (!trustStore.exists() && newDevice) {
            try {
                new File(userAlias + "_" + deviceName + "_" + "trustStore").mkdir();
                // Create a TrustStore
                KeyStore ts = KeyStore.getInstance("PKCS12");
                char[] passwordTrustStoreChar = passwordStores.toCharArray();
                ts.load(null, passwordTrustStoreChar);

                // Save the TrustStore to a file
                try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
                    ts.store(fos, passwordTrustStoreChar);
                }
            } catch (Exception e) {
                System.out.println("Error creating the TrustStore");
            }
        }

        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", passwordStores);

        // estabelecer ligacao - novo dispositivo (sem truststore)
        SocketFactory sf = SSLSocketFactory.getDefault();
        SSLSocket socket = null;
        try {
            socket = (SSLSocket) sf.createSocket("localhost", 12345);
            //iniciar streams
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            out.writeUTF("First MSG");
        } catch (Exception e) {
            System.out.println("Error in the server handshake.");
        }
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
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
