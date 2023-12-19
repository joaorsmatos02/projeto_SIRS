import utils.RequestTable;

import javax.crypto.Mac;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import javax.crypto.SecretKey;
import java.util.Random;

import static utils.utils.writeLogFile;

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
        writeLogFile("Server", "Server", "Starting Server...");

        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);


        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

        SecureMessageLib secureMessageLibDB = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath, "server_db", "serverrsa", "databasersa");

        SocketFactory sf = SSLSocketFactory.getDefault();
        SSLSocket dataBaseSocket = null;
        try {
            writeLogFile("Server", "Server", "Connecting to DataBase Server...");
            dataBaseSocket = (SSLSocket) sf.createSocket("localhost", 54321);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        ObjectOutputStream outDB = null;
        ObjectInputStream inDB = null;

        try {
            outDB = new ObjectOutputStream(dataBaseSocket.getOutputStream());
            inDB = new ObjectInputStream(dataBaseSocket.getInputStream());

            String serverRSAAlias = "serverrsa";
            KeyStore serverKS = KeyStore.getInstance("PKCS12");
            serverKS.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());

            Certificate serverCertificate = serverKS.getCertificate(serverRSAAlias);
            SecretKey secretKey = (SecretKey) serverKS.getKey("server_db_secret", keyStorePass.toCharArray());

            //Send the certificate and the associated HMAC
            outDB.writeObject(serverCertificate);
            byte[] HmacOfCertificate = ServerThread.calculateHMac(secretKey, serverCertificate);
            outDB.writeObject(HmacOfCertificate);
            outDB.flush();
            writeLogFile("Server", "DataBase", "Sending the certificate and the associated HMAC.\n" +
                    "Certificate: \n " + serverCertificate + "\nAssociated HMAC: " + HmacOfCertificate.toString());

            //Read the result flag > 0-Error; 1-Correct
            String resultFlag = inDB.readUTF();
            String decryptedResultFlag = secureMessageLibDB.unprotectMessage(resultFlag);
            writeLogFile("DataBase", "Server", "Reading the result flag...\nEncyptedResultFlag: " + resultFlag +
                            "\nDecryptedResultFlag: " + decryptedResultFlag);
            if(decryptedResultFlag.equals("0")) {
                System.out.println("Certificate validation error.");
                writeLogFile("Server", "Server", "Certificate validation error.");
                inDB.close();
                outDB.close();
                dataBaseSocket.close();
                System.exit(1);
            }

        } catch (Exception e) {
            e.printStackTrace();
            try {
                dataBaseSocket.close();
            } catch (IOException ex) {
                System.out.println("DataBase connection closed");
            }
        }

        ConfirmPaymentHandler confirmPaymentHandler = new ConfirmPaymentHandler();

        // create socket
        ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();

        try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port)) {

            while (true) {
                SSLSocket socket = (SSLSocket) ss.accept();
                ServerThread st = new ServerThread(socket, outDB, inDB, confirmPaymentHandler);
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
    private final ObjectOutputStream outDB;
    private final ObjectInputStream inDB;
    private final ConfirmPaymentHandler confirmPaymentHandler;

    public ServerThread(SSLSocket inSoc, ObjectOutputStream outDB, ObjectInputStream inDB, ConfirmPaymentHandler confirmPaymentHandler) {
        this.socket = inSoc;
        this.outDB = outDB;
        this.inDB = inDB;
        this.confirmPaymentHandler = confirmPaymentHandler;

    }

    @Override
    public void run() {

        System.out.println("Client connected");
        writeLogFile("Server", "Server", "Client connected");


        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            //userAlias + "_" + deviceName + "true(newDevice) "
            String clientIdentifier = in.readUTF();
            String[] clientIdentifierSplitted = clientIdentifier.split(" ");
            String userAndDevice = clientIdentifierSplitted[0];
            writeLogFile("Client", "Server", "ClientIdentifier: " + clientIdentifier);


            //2args == newDevice flag
            if(clientIdentifierSplitted.length == 2){
                Certificate clientCertificate = (Certificate) in.readObject();
                byte[] clientCertificateHMAC = (byte[]) in.readObject();
                writeLogFile("Client", "Server", "ClientCertificate: " + clientCertificate.toString()
                        + "\n clientCertificateHMAC: " + clientCertificateHMAC.toString());

                //Get SecretKey associated to current client
                KeyStore serverKS = KeyStore.getInstance("PKCS12");
                serverKS.load(new FileInputStream(new File(keyStorePath)), keyStorePass.toCharArray());
                SecretKey secretKey = (SecretKey) serverKS.getKey(userAndDevice + "_secret", keyStorePass.toCharArray());


                //Compromise HMAC Test - uncomment to test it.
                // Concatenate the byte array of character 'a' to clientCertificateHMAC
                /*byte[] testBytes = "a".getBytes(StandardCharsets.UTF_8);
                clientCertificateHMAC = Arrays.copyOf(clientCertificateHMAC, clientCertificateHMAC.length + testBytes.length);
                System.arraycopy(testBytes, 0, clientCertificateHMAC, clientCertificateHMAC.length - testBytes.length, testBytes.length);*/

                writeLogFile("Server", "Server", "Verifying the integrity of the received certificate...");
                if(!verifyHMac(secretKey, clientCertificate, clientCertificateHMAC)) {
                    writeLogFile("Server", "Server", "Corrupted Certificate. HMAC verification failed.");
                    System.out.println("Corrupted Certificate. HMAC verification failed.");
                    in.close();
                    out.close();
                    System.exit(1);
                }

                writeLogFile("Server", "Server", "HMAC verification > success.");
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

            SecureMessageLib secureMessageLibClient = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath, userAndDevice, "serverrsa",userAndDevice + "_cert" );
            SecureMessageLib secureMessageLibDB = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath, "server_db", "serverrsa", "databasersa");
            SecureDocumentLib secureDocumentLib = new SecureDocumentLib(keyStoreName, keyStorePass, keyStorePath);

            String encryptedClientAccount = in.readUTF();
            String clientAccount = secureMessageLibClient.unprotectMessage(encryptedClientAccount);
            writeLogFile("Client", "Server", "encryptedClientAccount: " + encryptedClientAccount +
                            "\nDecryptedClientAccount: " + clientAccount);

            RequestsHandler requestsHandler = new RequestsHandler(secureMessageLibDB, secureMessageLibClient, secureDocumentLib, this.outDB, this.inDB);

            //actions
            boolean isWorking = true;
            while(isWorking) {
                String encryptedMessage = in.readUTF();
                String decryptedMessage = secureMessageLibClient.unprotectMessage(encryptedMessage);
                writeLogFile("Client", "Server", "EncryptedMessage: " + encryptedMessage +
                        "\nDecryptedMessage: " + decryptedMessage);

                if (!decryptedMessage.equals("Error verifying signature")){
                    String[] userInput = decryptedMessage.split(" ");

                    if (userInput.length != 0) {
                        switch (userInput[0]) {
                            case "balance":
                                String resultBalance = requestsHandler.handleRequestBalance(clientAccount);
                                out.writeUTF(resultBalance);
                                out.flush();
                                writeLogFile("Server", "Client", "ResultBalance: " + resultBalance);
                                break;

                            case "movements":
                                String resultMovements = requestsHandler.handleRequestMovements(clientAccount);
                                out.writeUTF(resultMovements);
                                out.flush();
                                writeLogFile("Server", "Client", "resultMovements: " + resultMovements);
                                break;

                            case "make_movement":
                                String description = "";
                                for (int i = 2; i < userInput.length; i++) {
                                    description = description + userInput[i] + " ";
                                }
                                String resultMakeMovement = requestsHandler.handleRequestMakeMovement(clientAccount,userInput[1], description);
                                out.writeUTF(resultMakeMovement);
                                out.flush();
                                writeLogFile("Server", "Client", "ResultMakeMovement: " + resultMakeMovement);
                                break;

                            case "make_payment":
                                Random rnd = new Random();
                                String nonce = String.valueOf(rnd.nextInt());
                                String encryptedNonce = secureMessageLibClient.protectMessage(nonce);
                                out.writeUTF(encryptedNonce);
                                out.flush();
                                writeLogFile("Server", "Client", "EncryptedNonce: " + encryptedNonce +
                                                "\nDecryptedNonce: " + nonce);

                                String requestAndNonceEncrypted = in.readUTF();
                                String requestAndNonce = secureMessageLibClient.unprotectMessage(requestAndNonceEncrypted);
                                writeLogFile("Client", "Server", "RequestAndNonceEncrypted: " + requestAndNonceEncrypted +
                                        "\nRequestAndNonceDecrypted: " + requestAndNonce);

                                if(!requestAndNonce.equals("Error verifying signature")){
                                    String [] requestAndNonceSplit = requestAndNonce.split(" ");
                                    String request = "";
                                    String description1 = "";
                                    for (int i = 0; i < requestAndNonceSplit.length - 1; i++) {
                                        request = request + requestAndNonceSplit[i] + " ";
                                        if (i > 2){
                                            description1 = description1 + requestAndNonceSplit[i];
                                        }
                                    }

                                    if (nonce.equals(requestAndNonceSplit[requestAndNonceSplit.length - 1])){
                                        if (!RequestTable.hasEntry(request)) {
                                            RequestTable.addEntry(request);
                                            String answer = requestsHandler.handleRequestMakePayment(userAndDevice.split("_")[0], clientAccount, requestAndNonceSplit[1], description1, requestAndNonceSplit[2], confirmPaymentHandler);
                                            out.writeUTF(answer);
                                            out.flush();
                                        } else {
                                            out.writeUTF(secureMessageLibClient.protectMessage("Freshness Attack"));
                                        }
                                    }
                                } else {
                                    out.writeUTF(secureMessageLibClient.protectMessage("Error verifying signature"));
                                }
                                break;

                            case "payments":
                                String resultPayments = requestsHandler.handleRequestPayments(clientAccount);
                                out.writeUTF(resultPayments);
                                out.flush();
                                break;

                            case "payments_to_confirm":
                                String resultPaymentsToConfirm = requestsHandler.handleRequestPaymentsToConfirm(userAndDevice.split("_")[0], confirmPaymentHandler);
                                out.writeUTF(resultPaymentsToConfirm);
                                out.flush();
                                break;

                            case "confirm_payment":
                                String resultPaymentConfirmation = requestsHandler.handleRequestConfirmPayment(userAndDevice.split("_")[0], userInput[1], confirmPaymentHandler);
                                out.writeUTF(resultPaymentConfirmation);
                                out.flush();
                                break;

                            case "exit":
                                isWorking = false;
                                in.close();
                                out.close();
                                break;

                            default:
                                System.out.println("Error: Unrecognized command. Please check your input.");
                                break;
                        }
                    }
                } else {
                    out.writeUTF(secureMessageLibClient.protectMessage("Wrong signature"));
                    out.flush();
                }

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