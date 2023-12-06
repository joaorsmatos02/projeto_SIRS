import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
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
import javax.crypto.SecretKey;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class SSLServer {

    private static final int port = 12345;

    private static final String keyStoreName = "serverKeyStore";
    private static final String keyStorePass = "serverKeyStore";
    private static final String keyStorePath = "serverKeyStore//" + keyStoreName;

    private static final String privateKeyAlias = "pk";

    private static final String trustStoreName = "serverTrustStore";
    private static final String trustStorePass = "serverTrustStore";
    private static final String trustStorePath = "serverTrustStore//" + trustStoreName;

    public static void main(String[] args) throws Exception {

        System.out.println("Starting server...");

        // setup keystore
        File keyStore = new File(keyStorePath);

        //SÓ PARA DEBUG AGORA A GUARDA DO IF!!
        if(!keyStore.exists()) {
            try {

                /*new File("serverKeyStore").mkdir();*/

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

                //alterar argumento Certificado, meter lá dentro selfSignedCert
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
                new File("serverTrustStore").mkdir();

                // Create a TrustStore
                KeyStore ts = KeyStore.getInstance("PKCS12");
                char[] password = trustStorePass.toCharArray();
                ts.load(null, password);
                trustStore.createNewFile();
                // Save the TrustStore to a file
                try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
                    ts.store(fos, password);
                }
            } catch (Exception e) {
                System.out.println("Error creating the TrustStore");

            }
        }

        /*System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);*/

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

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        // Get the current date
        Date startDate = new Date();

        // Set the validity period of the certificate (e.g., 365 days)
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000);

        // Generate a self-signed X.509 certificate
        X509Certificate cert = null;
        try {
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    new X500Name("CN=Self-Signed Certificate"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    startDate,
                    endDate,
                    new X500Name("CN=Self-Signed Certificate"),
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

            // Set the key usage extension (optional)
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            // Sign the certificate
            cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));

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

            System.out.println(in.readUTF());

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