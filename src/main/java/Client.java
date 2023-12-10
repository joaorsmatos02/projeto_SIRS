import javax.crypto.Mac;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.SecretKey;
import java.security.KeyStore.SecretKeyEntry;

public class Client {

    public static void main(String[] args) {

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

        String userStoresFolder = "Client//" + userAlias + "_" + deviceName;
        String keyStoreName = userAlias + "_" + deviceName + "_KeyStore";
        String keyStorePath = userStoresFolder + "//" + keyStoreName;

        String privateKeyAlias = "pk";

        String trustStoreName = userAlias + "_" + deviceName + "_TrustStore";
        String trustStorePath = "Client//" + userAlias + "_" + deviceName + "//" + trustStoreName;

        // setup keystore
        File stores = new File(userStoresFolder);

        if (!stores.exists() && newDevice) {
            try {
                new File("Client").mkdir();
                new File(userStoresFolder).mkdir();

                // Generate RSA keys + keystore
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

                //Get secretKey between client<->bank
                KeyStore serverKS = KeyStore.getInstance("PKCS12");
                serverKS.load(new FileInputStream(new File("Server/serverKeyStore/serverKeyStore")), "serverKeyStore".toCharArray());
                SecretKey secretKey = (SecretKey) serverKS.getKey(userAlias + "_" + deviceName + "_secret", "serverKeyStore".toCharArray());

                //Import to the client KeyStore
                KeyStore clientKS = KeyStore.getInstance("PKCS12");
                clientKS.load(new FileInputStream(new File(keyStorePath)), passwordStores.toCharArray());
                KeyStore.SecretKeyEntry skEntry = new SecretKeyEntry(secretKey);
                clientKS.setEntry(userAlias + "_" + deviceName + "_secret", skEntry, new KeyStore.PasswordProtection(passwordStores.toCharArray()));

                FileOutputStream fos = null;
                try {
                    fos = new FileOutputStream(keyStorePath);
                    clientKS.store(fos, passwordStores.toCharArray());
                } finally {
                    if (fos != null) {
                        fos.close();
                    }
                }

            }  catch (IOException | InterruptedException | KeyStoreException | NoSuchAlgorithmException |
                      CertificateException | UnrecoverableKeyException e) {
                System.out.println("Error creating KeyStore.");
            }

            // Create a TrustStore with the certificate of the server
            try {
                //alterar path para CA
                String certificateFile = "CAserver/serverCert.cer";
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
            } catch (IOException | InterruptedException e){
                System.out.println("Error creating TrustStore.");
            }
        }

        //keystore
        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", passwordStores);

        //truststore
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", passwordStores);


        SocketFactory sf = SSLSocketFactory.getDefault();
        SSLSocket socket = null;
        try {
            socket = (SSLSocket) sf.createSocket("localhost", 12345);
            //iniciar streams
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            //send
            if(newDevice) {
                KeyStore clientKS = KeyStore.getInstance("PKCS12");
                clientKS.load(new FileInputStream(new File(keyStorePath)), passwordStores.toCharArray());

                out.writeUTF(userAlias + "_" + deviceName + " true");

                Certificate clientCertificate = clientKS.getCertificate(userAlias+"rsa");
                SecretKey secretKey = (SecretKey) clientKS.getKey(userAlias + "_" + deviceName + "_secret", (userAlias + "_" + deviceName).toCharArray());

                //send the certificate and the associated HMAC
                out.writeObject(clientCertificate);
                out.writeObject(calculateHMac(secretKey, clientCertificate));
                out.flush();
            } else {
                out.writeUTF(userAlias + "_" + deviceName);
            }

        } catch (Exception e) {
            System.out.println("Error in the server handshake.");
        }
    }

    public static byte[] calculateHMac(SecretKey secretKey, Certificate certificate) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(certificate.getEncoded());
    }
}
