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
import java.util.Scanner;

import static utils.utils.writeLogFile;

public class Client {

    public static void main(String[] args) {

        if (args.length != 5) {
            System.out.println("Wrong args. Use help command.");
            System.exit(1);
        }

        System.out.println("Starting client...");

        //args: 0-userAlias | 1-password | 2-newDevice(0-false or 1-true)| 3-deviceName | 4- account
        String userAlias = args[0];
        String passwordStores = args[1];
        boolean newDevice = "1".equals(args[2]);
        String deviceName = args[3];
        String account = args[4];

        String [] usersFromAccount = account.split("_");

        boolean validUser = false;

        for (int i = 0; i < usersFromAccount.length; i++) {
            if(usersFromAccount[i].equals(userAlias)){
                validUser = true;
            }
        }

        if (!validUser){
            System.exit(1);
        }

        String userStoresFolder = "Client//" + userAlias + "_" + deviceName;
        String keyStoreName = userAlias + "_" + deviceName + "_KeyStore";
        String keyStorePath = userStoresFolder + "//" + keyStoreName;

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
            SecureMessageLib secureMessageLib = new SecureMessageLib(passwordStores, keyStorePath,
                    passwordStores, trustStorePath, userAlias + "_" + deviceName, userAlias + "rsa", "serverrsa");

            socket = (SSLSocket) sf.createSocket("localhost", 12345);
            //iniciar streams
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            //send
            if(newDevice) {
                KeyStore clientKS = KeyStore.getInstance("PKCS12");
                clientKS.load(new FileInputStream(new File(keyStorePath)), passwordStores.toCharArray());

                //userAlias + "_" + deviceName + "true(newDevice) "
                out.writeUTF(userAlias + "_" + deviceName + " true");
                writeLogFile("Client", "Server", "ClientIdentifier: " + userAlias + "_" + deviceName);


                Certificate clientCertificate = clientKS.getCertificate(userAlias+"rsa");
                SecretKey secretKey = (SecretKey) clientKS.getKey(userAlias + "_" + deviceName + "_secret", (userAlias + "_" + deviceName).toCharArray());

                byte [] HmacOfCertificate = calculateHMac(secretKey, clientCertificate);
                //send the certificate and the associated HMAC
                out.writeObject(clientCertificate);
                out.writeObject(HmacOfCertificate);
                out.flush();

                writeLogFile("Client", "Server", "Sending the certificate and the associated HMAC.\n" +
                        "Certificate: \n " + clientCertificate + "\nAssociated HMAC: " + HmacOfCertificate.toString());

            } else {
                out.writeUTF(userAlias + "_" + deviceName);
                out.flush();
                writeLogFile("Client", "Server", "ClientIdentifier: " + userAlias + "_" + deviceName);
            }

            String encryptedAccount = secureMessageLib.protectMessage(account);
            out.writeUTF(encryptedAccount);
            out.flush();

            writeLogFile("Client", "Server", "encryptedClientAccount: " + encryptedAccount +
                    "\nDecryptedClientAccount: " + account);

            Scanner scanner = new Scanner(System.in);

            //Print Menu of commands
            printMenu(userAlias);

            //Actions
            while(true) {
                String userInput = scanner.nextLine();
                String[] input = userInput.split(" ");
                if (input.length != 0){
                    switch (input[0]) {
                        case "balance", "movements", "payments", "payments_to_confirm":
                            if(input.length == 1) {
                                String encryptedPayload = secureMessageLib.protectMessage(userInput);
                                if (!encryptedPayload.equals("Encryption Failed")){
                                    out.writeUTF(encryptedPayload);
                                    out.flush();
                                    writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayload +
                                            "\nDecryptedPayload: " + userInput);
                                    String encryptedAnswer = in.readUTF();
                                    String answer = secureMessageLib.unprotectMessage(encryptedAnswer);
                                    writeLogFile("Server", "Client", "EncryptedPayload: " + encryptedAnswer +
                                            "\nDecryptedPayload: " + answer);
                                    System.out.println(answer);
                                    System.out.print("Next command: ");
                                } else {
                                    System.out.println("Encryption Failed");
                                    printMenu(userAlias);
                                }
                            } else {
                                System.out.println("Error: Unrecognized command. Please check your input.");
                                printMenu(userAlias);
                            }
                            break;

                        case "make_movement":
                            if(input.length >= 3 && (input[1].matches("\\d+(\\.\\d{1,2})?") && Double.parseDouble(input[1]) > 0)) {
                                String encryptedPayload = secureMessageLib.protectMessage(userInput);
                                if (!encryptedPayload.equals("Encryption Failed")){
                                    out.writeUTF(encryptedPayload);
                                    out.flush();
                                    writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayload +
                                            "\nDecryptedPayload: " + userInput);
                                    String encryptedAnswer = in.readUTF();
                                    String answer = secureMessageLib.unprotectMessage(encryptedAnswer);
                                    writeLogFile("Server", "Client", "EncryptedPayload: " + encryptedAnswer +
                                            "\nDecryptedPayload: " + answer);
                                    System.out.println(answer);
                                    System.out.print("Next command: ");
                                } else {
                                    System.out.println("Encryption Failed");
                                    printMenu(userAlias);
                                }
                            } else {
                                System.out.println("Error: Unrecognized command. Please check your input.");
                                printMenu(userAlias);
                            }
                            break;

                        case "make_payment":
                            if(input.length >= 4 && (input[1].matches("\\d+(\\.\\d{1,2})?") && Double.parseDouble(input[1]) > 0) && existingAccountDifFromSelf(userAlias, input[2])) {
                                String encryptedPayload = secureMessageLib.protectMessage("make_payment");
                                out.writeUTF(encryptedPayload);
                                out.flush();
                                writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayload +
                                        "\nDecryptedPayload: make_payment");
                                String encryptedNonce = in.readUTF();
                                String nonce = secureMessageLib.unprotectMessage(encryptedNonce);
                                writeLogFile("Server", "Client", "EncryptedPayload: " + encryptedNonce +
                                        "\nDecryptedPayload: " + nonce);
                                if(!nonce.equals("Wrong signature")){
                                    String encryptedPayloadWithNonce = secureMessageLib.protectMessage(userInput + " " + nonce);
                                    out.writeUTF(encryptedPayloadWithNonce);
                                    out.flush();
                                    writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayloadWithNonce +
                                            "\nDecryptedPayload: " + userInput + " " + nonce);
                                    String encryptedAnswer = in.readUTF();
                                    String answer = secureMessageLib.unprotectMessage(encryptedAnswer);

                                    writeLogFile("Server", "Client", "EncryptedPayload: " + encryptedAnswer +
                                            "\nDecryptedPayload: " + answer);

                                    System.out.println(answer);
                                    System.out.print("Next command: ");
                                } else {
                                    System.out.println(nonce);
                                    System.out.print("Next command: ");
                                }

                            } else {
                                System.out.println("Error: Unrecognized destiny account or command. Please check your input.");
                                printMenu(userAlias);
                            }
                            break;

                        case "confirm_payment":
                            if(input.length == 2 && Integer.parseInt(input[1]) >= 0) {
                                String encryptedPayload = secureMessageLib.protectMessage(userInput);
                                if (!encryptedPayload.equals("Encryption Failed")){
                                    out.writeUTF(encryptedPayload);
                                    out.flush();

                                    writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayload +
                                            "\nDecryptedPayload: " + userInput);

                                    String encryptedAnswer = in.readUTF();
                                    String answer = secureMessageLib.unprotectMessage(encryptedAnswer);
                                    writeLogFile("Server", "Client", "EncryptedPayload: " + encryptedAnswer +
                                            "\nDecryptedPayload: " + answer);
                                    System.out.println(answer);
                                    System.out.print("Next command: ");
                                } else {
                                    System.out.println("Encryption Failed");
                                    printMenu(userAlias);
                                }
                            } else {
                                System.out.println("Error: Unrecognized command. Please check your input.");
                                printMenu(userAlias);
                            }
                            break;

                        case "exit":
                            System.out.print("Closing BlingBank...");
                            String encryptedPayload = secureMessageLib.protectMessage("exit");
                            out.writeUTF(encryptedPayload);
                            out.flush();

                            writeLogFile("Client", "Server", "EncryptedPayload: " + encryptedPayload +
                                    "\nDecryptedPayload: exit");

                            System.exit(0);

                        default:
                            System.out.println("Error: Unrecognized command. Please check your input.");
                            printMenu(userAlias);
                            break;
                    }
                }


            }

        } catch (Exception e) {
            System.out.println("Error in the server handshake.");
        }
    }


    private static void printMenu(String userAlias) {
        System.out.println("Welcome " + userAlias + "!\n" +
                "Here you have the list of commands you can execute:\n" +
                " - In order to see your balance, write the following command > balance\n" +
                " - In order to see your movements, write the following command > movements\n" +
                " - In order to make a movement, write the following command adding the value and the description > make_movement <value> <description>\n" +
                " - In order to make a payment, write the following command adding the value, destiny account (alias name) and description make_payment > make_payment <value> <destinyAccount> <description>\n" +
                " - In order to see your payments, write the following command > payments\n" +
                " - In order to see your pending payments, write the following command > payments_to_confirm\n" +
                " - In order to confirm your pending payments, write the following command > confirm_payment <Payment ID>");
    }

    public static byte[] calculateHMac(SecretKey secretKey, Certificate certificate) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(certificate.getEncoded());
    }

    private static boolean existingAccountDifFromSelf(String currentClient, String paymentToAccount) {
        return (paymentToAccount.equals("alice") || paymentToAccount.equals("bob") || paymentToAccount.equals("mario") || paymentToAccount.equals("alcides") || paymentToAccount.equals("alice_bob")) && !paymentToAccount.equals(currentClient);
    }
}
