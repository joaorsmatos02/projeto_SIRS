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

        SocketFactory sf = SSLSocketFactory.getDefault();
        SSLSocket dataBaseSocket = null;
        try {
            dataBaseSocket = (SSLSocket) sf.createSocket("localhost", 54321);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        ObjectOutputStream outDB = null;
        ObjectInputStream inDB = null;

        try {
            outDB = new ObjectOutputStream(dataBaseSocket.getOutputStream());
            inDB = new ObjectInputStream(dataBaseSocket.getInputStream());
            //Send the Certificate (with HMAC) from Server to DB
            String serverRSAAlias = "serverrsa";
            KeyStore serverKS = KeyStore.getInstance("PKCS12");
            serverKS.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());

            Certificate serverCertificate = serverKS.getCertificate(serverRSAAlias);
            SecretKey secretKey = (SecretKey) serverKS.getKey("server_db_secret", keyStorePass.toCharArray());
            //send the certificate and the associated HMAC
            outDB.writeObject(serverCertificate);
            outDB.writeObject(ServerThread.calculateHMac(secretKey, serverCertificate));
            outDB.flush();

            //Read the result flag > 0-Error; 1-Correct
            String resultFlag = inDB.readUTF();
            if(resultFlag.equals("0")) {
                System.out.println("Certificate validation error.");
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
                ServerThread st = new ServerThread(socket, dataBaseSocket, outDB, inDB, confirmPaymentHandler);
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
    private final SSLSocket dataBaseSocket;
    private final ObjectOutputStream outDB;
    private final ObjectInputStream inDB;
    private final ConfirmPaymentHandler confirmPaymentHandler;

    public ServerThread(SSLSocket inSoc, SSLSocket dataBaseSocket, ObjectOutputStream outDB, ObjectInputStream inDB, ConfirmPaymentHandler confirmPaymentHandler) {
        this.socket = inSoc;
        this.dataBaseSocket = dataBaseSocket;
        this.outDB = outDB;
        this.inDB = inDB;
        this.confirmPaymentHandler = confirmPaymentHandler;

    }

    @Override
    public void run() {

        System.out.println("Client connected");
        
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String clientIdentifier = in.readUTF();
            //userAlias + "_" + deviceName + "true(newDevice) "
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


            String clientAccount = in.readUTF();
            SecureMessageLib secureMessageLibClient = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath, userAndDevice, "serverrsa",userAndDevice + "_cert" );
            SecureMessageLib secureMessageLibDB = new SecureMessageLib(keyStorePass, keyStorePath, trustStorePass, trustStorePath, "server_db", "serverrsa", "databasersa");
            SecureDocumentLib secureDocumentLib = new SecureDocumentLib(keyStoreName, keyStorePass, keyStorePath);
            RequestsHandler requestsHandler = new RequestsHandler(secureMessageLibDB, secureMessageLibClient, secureDocumentLib, this.outDB, this.inDB);

            //actions
            while(true) {
                String encryptedMessage = in.readUTF();
                String decryptedMessage = secureMessageLibClient.unprotectMessage(encryptedMessage);
                if (!decryptedMessage.equals("Error verifying signature")){
                    String[] userInput = decryptedMessage.split(" ");

                    if (userInput.length != 0) {
                        // Case 0, no update on DB, case 1, new DB update
                        String updateDBFlag;
                        String encryptedAccount;
                        switch (userInput[0]) {
                            case "balance":
                                String resultBalance = requestsHandler.handleRequestBalance(clientAccount);
                                out.writeUTF(resultBalance);
                                out.flush();
                                break;

                            case "movements":
                                String resultMovements = requestsHandler.handleRequestMovements(clientAccount);
                                out.writeUTF(resultMovements);
                                out.flush();
                                break;

                            case "make_movement":
                                String description = "";
                                for (int i = 2; i < userInput.length; i++) {
                                    description = description + userInput[i] + " ";
                                }
                                String resultMakeMovement = requestsHandler.handleRequestMakeMovement(clientAccount,userInput[1], description);
                                out.writeUTF(resultMakeMovement);
                                out.flush();
                                break;

                            case "make_payment":
                                Random rnd = new Random();
                                String nonce = String.valueOf(rnd.nextInt());
                                out.writeUTF(secureMessageLibClient.protectMessage(nonce));
                                out.flush();

                                String requestAndNonce = secureMessageLibClient.unprotectMessage(in.readUTF());
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
                                String resultPaymentConfirmation = requestsHandler.handleRequestConfirmPayment(clientAccount, userAndDevice.split("_")[0], userInput[1], confirmPaymentHandler);
                                out.writeUTF(resultPaymentConfirmation);
                                out.flush();
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