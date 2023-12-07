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

        String userStoresFolder = userAlias + "_" + deviceName;
        String keyStoreName = userAlias + "_" + deviceName + "_KeyStore";
        String keyStorePath = userStoresFolder + "//" + keyStoreName;

        String privateKeyAlias = "pk";

        String trustStoreName = userAlias + "_" + deviceName + "_TrustStore";
        String trustStorePath = userAlias + "_" + deviceName + "//" + trustStoreName;

        // setup keystore
        File stores = new File(userStoresFolder);

        if (!stores.exists() && newDevice) {
            try {
                new File(userStoresFolder).mkdir();

                // Generate RSA keys + keystore
                try {
                    ProcessBuilder processBuilder = new ProcessBuilder(
                            "keytool",
                            "-genkeypair",
                            "-alias", userAlias+"RSA",
                            "-keyalg", "RSA",
                            "-keysize", "2048",
                            "-storetype", "PKCS12",
                            "-keystore", keyStorePath
                    );

                    // Redirect error stream to output stream
                    processBuilder.redirectErrorStream(true);

                    Process process = processBuilder.start();

                    // Send the password to the process (if needed)
                    try (OutputStream outputStream = process.getOutputStream()) {
                        outputStream.write((passwordStores + "\n").getBytes());
                        outputStream.write((passwordStores +"\n").getBytes());
                        for (int i = 0; i < 6; i++) {
                            outputStream.write(("\n").getBytes());
                        }
                        outputStream.write(("yes" + "\n").getBytes());
                        outputStream.flush();
                    }

                    int exitCode = process.waitFor();

                    if (exitCode == 0) {
                        System.out.println("RSA & keystore generated successfully.");
                    } else {
                        System.out.println("Error in RSA & keystore generation. Exit code: " + exitCode);
                    }
                } catch (IOException | InterruptedException e) {
                    System.out.println("Error executing keytool: " + e.getMessage());
                }

            }  catch (Exception e) {
                System.out.println(e);
            }

            // Create a TrustStore with the certificate of the server
            try {
                //alterar path para CA
                String certificateFile = "serverKeyStore/serverCert.cer";

                try {
                    ProcessBuilder processBuilder = new ProcessBuilder(
                            "keytool",
                            "-importcert",
                            "-alias", "serverrsa",
                            "-file", certificateFile,
                            "-storetype", "PKCS12",
                            "-keystore", trustStorePath
                    );

                    // Redirect error stream to output stream
                    processBuilder.redirectErrorStream(true);

                    Process process = processBuilder.start();

                    // Send the password to the process (if needed)
                    try (OutputStream outputStream = process.getOutputStream()) {
                        outputStream.write((passwordStores + "\n").getBytes());
                        outputStream.write((passwordStores + "\n").getBytes());
                        outputStream.write(("yes" + "\n").getBytes());
                        outputStream.flush();
                    }

                    int exitCode = process.waitFor();

                    if (exitCode == 0) {
                        System.out.println("Certificate added to the truststore successfully.");
                    } else {
                        System.out.println("Error adding the certificate to the truststore. Exit code: " + exitCode);
                    }
                } catch (Exception e) {
                    System.out.println("Error executing keytool: " + e.getMessage());
                }
            } catch (Exception e){
                System.out.println("Error creating the truststore. " + e.getMessage());
            }
        }


        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", passwordStores);

        // setup truststore
        File trustStore = new File(trustStorePath);

        if (!trustStore.exists() && newDevice) {

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
