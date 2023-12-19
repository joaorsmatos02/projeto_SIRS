import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import dto.SignedObjectDTO;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;

import static utils.utils.writeLogFile;

public class RequestsHandler {
    private final SecureMessageLib secureMessageLibDB;
    private final SecureMessageLib secureMessageLibClient;
    private final SecureDocumentLib secureDocumentLib;
    private final ObjectOutputStream outDB;
    private final ObjectInputStream inDB;

    public RequestsHandler(SecureMessageLib secureMessageLibDB, SecureMessageLib secureMessageLibClient, SecureDocumentLib secureDocumentLib, ObjectOutputStream outDB, ObjectInputStream inDB) {
        this.secureMessageLibDB = secureMessageLibDB;
        this.secureMessageLibClient = secureMessageLibClient;
        this.secureDocumentLib = secureDocumentLib;
        this.outDB = outDB;
        this.inDB = inDB;
    }

    public String handleRequestBalance(String clientAccount) {
        synchronized (outDB){
            synchronized (inDB){
                try {
                    // Case 0, no update on DB, case 1, new DB update
                    String updateDBFlag = secureMessageLibDB.protectMessage("0");
                    String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
                    String encryptedDocType = secureMessageLibDB.protectMessage("account");
                    if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed") && !encryptedDocType.equals("Encryption Failed")) {
                        outDB.writeUTF(updateDBFlag);
                        outDB.writeUTF(encryptedAccount);
                        outDB.writeUTF(encryptedDocType);
                        outDB.flush();
                        writeLogFile("Server", "DataBase", "EncryptedUpdateDBFlag: " + updateDBFlag +
                                "\nDecryptedUpdateDBFlag: 0" +
                                "\n----\nEncryptedAccount: " + encryptedAccount +
                                "\nDecryptedAccount: " + clientAccount +
                                "\n----\nEncryptedDocType: " + encryptedDocType +
                                "\nDecryptedDocType: account");

                        String account = inDB.readUTF();
                        String result = secureMessageLibDB.unprotectMessage(account);

                        byte[] messageDecoded = Base64.getDecoder().decode(result);

                        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                        SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                        JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                        JsonObject accountObject = object.getAsJsonObject("account");

                        writeLogFile("DataBase", "Server", "EncryptedAccount: " + account +
                                "\nDecryptedAccount: " + accountObject.toString());

                        double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                        String resultMessage = "Your balance is: " + balance + "\n";

                        return secureMessageLibClient.protectMessage(resultMessage);

                    }
                } catch (Exception e) {
                    return "Error";
                }
                return "Error";
            }
        }
    }

    public String handleRequestMovements(String clientAccount) {
        synchronized (outDB) {
            synchronized (inDB) {
                try {
                // Case 0, no update on DB, case 1, new DB update
                String updateDBFlag = secureMessageLibDB.protectMessage("0");
                String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
                String encryptedDocType = secureMessageLibDB.protectMessage("account");
                if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed") && !encryptedDocType.equals("Encryption Failed")) {
                    outDB.writeUTF(updateDBFlag);
                    outDB.writeUTF(encryptedAccount);
                    outDB.writeUTF(encryptedDocType);
                    outDB.flush();
                    writeLogFile("Server", "DataBase", "EncryptedUpdateDBFlag: " + updateDBFlag +
                            "\nDecryptedUpdateDBFlag: 0" +
                            "\n----\nEncryptedAccount: " + encryptedAccount +
                            "\nDecryptedAccount: " + clientAccount +
                            "\n----\nEncryptedDocType: " + encryptedDocType +
                            "\nDecryptedDocType: account");

                    String account = inDB.readUTF();
                    String result = secureMessageLibDB.unprotectMessage(account);

                    byte[] messageDecoded = Base64.getDecoder().decode(result);

                    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                    SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                    JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                    JsonObject accountObject = object.getAsJsonObject("account");

                    writeLogFile("DataBase", "Server", "EncryptedAccount: " + account +
                            "\nDecryptedAccount: " + accountObject.toString());

                    JsonArray movementsArray = accountObject.getAsJsonArray("movements");

                    String resultMessage = "";

                    for (JsonElement movementElement : movementsArray) {
                        JsonObject movementObject = movementElement.getAsJsonObject();

                        String date = movementObject.getAsJsonPrimitive("date").getAsString();
                        double value = movementObject.getAsJsonPrimitive("value").getAsDouble();
                        String description = movementObject.getAsJsonPrimitive("description").getAsString();

                        resultMessage = resultMessage + "Movement\n" + "Date: " + date + "\nValue: " + value + "\nDescription: " + description + "\n\n";
                    }

                    return secureMessageLibClient.protectMessage(resultMessage);
                }
            } catch (Exception e) {
                return "Error";
            }
                return "Error";
            }
        }


    }


    public String handleRequestMakeMovement(String clientAccount, String value, String description) {
        synchronized (outDB){
            synchronized (inDB){
                try {
                    // Case 0, no update on DB, case 1, new DB update
                    String updateDBFlag = secureMessageLibDB.protectMessage("1");
                    String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
                    String encryptedRequest = secureMessageLibDB.protectMessage("movement");
                    if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed")) {

                        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
                        Date currentDate = new Date();
                        String date = dateFormat.format(currentDate);

                        JsonObject movement = new JsonObject();

                        movement.addProperty("date", date);
                        movement.addProperty("value", "-" + value);
                        movement.addProperty("description", description);

                        outDB.writeUTF(updateDBFlag);
                        outDB.writeUTF(encryptedAccount);
                        outDB.writeUTF(encryptedRequest);
                        outDB.flush();
                        writeLogFile("Server", "DataBase", "EncryptedUpdateDBFlag: " + updateDBFlag +
                                "\nDecryptedUpdateDBFlag: 1" +
                                "\n----\nEncryptedAccount: " + encryptedAccount +
                                "\nDecryptedAccount: " + clientAccount +
                                "\n----\nEncryptedRequest: " + encryptedRequest +
                                "\nDecryptedRequest: movement");

                        //get the account to get the iv
                        String account = inDB.readUTF();
                        String result = secureMessageLibDB.unprotectMessage(account);

                        byte[] messageDecoded = Base64.getDecoder().decode(result);

                        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                        SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                        JsonObject objectAccountDecrypted = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                        JsonObject accountObject = objectAccountDecrypted.getAsJsonObject("account");

                        writeLogFile("DataBase", "Server", "EncryptedAccount: " + account +
                                "\nDecryptedAccount: " + accountObject.toString());

                        double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                        if (balance >= Double.parseDouble(value)) {
                            String encryptedConfirmationFlag = secureMessageLibDB.protectMessage("ok");
                            outDB.writeUTF(encryptedConfirmationFlag);
                            writeLogFile("Server", "DataBase", "EncryptedConfirmationFlag: " + encryptedConfirmationFlag +
                                    "\nDecryptedConfirmationFlag: ok");

                            JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, false, "account");

                            String ivAndEncryptedBalanceStr = object.getAsJsonPrimitive("encryptedBalance").getAsString();
                            byte[] ivAndEncryptedBalance = Base64.getDecoder().decode(ivAndEncryptedBalanceStr);

                            // Separate IV and encryptedBalance
                            byte[] iv = Arrays.copyOfRange(ivAndEncryptedBalance, 0, 16); // 16 bytes for the IV

                            String encryptedBalance = secureMessageLibDB.protectMessage(secureDocumentLib.encryptBalance(String.valueOf((balance - Double.parseDouble(value))), clientAccount, iv));
                            outDB.writeUTF(encryptedBalance);
                            String encryptedMovements = secureMessageLibDB.protectMessage(secureDocumentLib.encryptMovement(movement, clientAccount, iv));
                            outDB.writeUTF(encryptedMovements);
                            outDB.flush();
                            writeLogFile("Server", "DataBase", "EncryptedBalance: " + encryptedBalance
                                        + "EncryptedMovements: " + encryptedMovements);

                            String encryptedResultFromDB = inDB.readUTF();
                            String resultFromDB = secureMessageLibDB.unprotectMessage(encryptedResultFromDB);
                            writeLogFile("DataBase", "Server", "ResultFromDB: " + encryptedResultFromDB);

                            return secureMessageLibClient.protectMessage(resultFromDB);
                        } else {
                            String encryptedStopFlag = secureMessageLibDB.protectMessage("stop");
                            outDB.writeUTF(encryptedStopFlag);
                            writeLogFile("Server", "DataBase", "EncryptedStopFlag: " + encryptedStopFlag);
                            return secureMessageLibClient.protectMessage("You dont have balance to make that movement");
                        }

                    }
                } catch (Exception e) {
                    return "Error";
                }
                return "Error";
            }
        }

    }


    public String handleRequestMakePayment(String userMakingPayment, String clientAccount, String value, String description, String destinyAccount, ConfirmPaymentHandler confirmPaymentHandler) {

        if (clientAccount.split("_").length == 1) {
            return payment(clientAccount, value, description, destinyAccount);
        } else {

            return waitingConfirm(userMakingPayment, clientAccount, value, description, destinyAccount, confirmPaymentHandler);
        }
    }

    private String waitingConfirm(String userMakingPayment, String clientAccount, String value, String description, String destinyAccount, ConfirmPaymentHandler confirmPaymentHandler) {
        String [] usersFromAccount = clientAccount.split("_");
        List<String> usersToConfirm = new ArrayList<>();
        for(String user : usersFromAccount){
            if(!user.equals(userMakingPayment)){
                usersToConfirm.add(user);
            }
        }

        confirmPaymentHandler.addEntry(usersToConfirm, value, description, destinyAccount, clientAccount);
        String result = "Waiting for ";

        for (int i = 0; i < usersToConfirm.size(); i++) {
            if (i < usersToConfirm.size() - 1) {
                result = result + usersToConfirm + " and ";
            } else {
                result = result + usersToConfirm + " confirmation \n";
            }
        }

        return secureMessageLibClient.protectMessage(result);
    }


    public String payment(String clientAccount, String value, String description, String destinyAccount) {
        synchronized (outDB){
            synchronized (inDB){
                try {
                    SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
                    Date currentDate = new Date();
                    String date = dateFormat.format(currentDate);

                    String updateDBFlag = secureMessageLibDB.protectMessage("1");
                    String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
                    String encryptedRequest = secureMessageLibDB.protectMessage("payment");

                    outDB.writeUTF(updateDBFlag);
                    outDB.writeUTF(encryptedAccount);
                    outDB.writeUTF(encryptedRequest);
                    outDB.flush();

                    writeLogFile("Server", "DataBase", "EncryptedUpdateDBFlag: " + updateDBFlag +
                            "\nDecryptedUpdateDBFlag: 1" +
                            "\n----\nEncryptedAccount: " + encryptedAccount +
                            "\nDecryptedAccount: " + clientAccount +
                            "\n----\nEncryptedRequest: " + encryptedRequest +
                            "\nDecryptedRequest: payment");

                    //get the account to get the iv
                    String account = inDB.readUTF();
                    String result = secureMessageLibDB.unprotectMessage(account);

                    byte[] messageDecoded = Base64.getDecoder().decode(result);

                    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                    SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                    JsonObject objectAccountDecrypted = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                    JsonObject accountObject = objectAccountDecrypted.getAsJsonObject("account");

                    writeLogFile("DataBase", "Server", "EncryptedAccount: " + account +
                            "\nDecryptedAccount: " + accountObject.toString());

                    double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                    if (balance >= Double.parseDouble(value)) {
                        String encryptedConfirmationFlag = secureMessageLibDB.protectMessage("ok");
                        outDB.writeUTF(encryptedConfirmationFlag);
                        outDB.flush();
                        writeLogFile("Server", "DataBase", "EncryptedConfirmationFlag: " + encryptedConfirmationFlag +
                                "\nDecryptedConfirmationFlag: ok");

                        String payment = inDB.readUTF();
                        String paymentResult = secureMessageLibDB.unprotectMessage(payment);
                        writeLogFile("DataBase", "Server", "EncryptedPayment: " + payment +
                                "\nDecryptedPayment: " + paymentResult);

                        byte[] paymentMessageDecoded = Base64.getDecoder().decode(paymentResult);

                        ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(paymentMessageDecoded));
                        SignedObjectDTO signedObjectDTOPayment = (SignedObjectDTO) ois2.readObject();

                        JsonObject objectAccountPaymentEncryptedOneLayer = secureDocumentLib.unprotect(signedObjectDTOPayment, clientAccount, false, "payment");

                        String ivAndEncryptedPaymentNumberStr = objectAccountPaymentEncryptedOneLayer.getAsJsonPrimitive("encryptedPaymentNumbers").getAsString();
                        byte[] ivAndEncryptedPaymentNumber = Base64.getDecoder().decode(ivAndEncryptedPaymentNumberStr);

                        // Separate IV and encryptedPaymentNumber
                        byte[] iv = Arrays.copyOfRange(ivAndEncryptedPaymentNumber, 0, 16); // 16 bytes for the IV

                        JsonObject newPayment = new JsonObject();

                        newPayment.addProperty("date", date);
                        newPayment.addProperty("value", "-" + value);
                        newPayment.addProperty("description", description);
                        JsonArray jsonArray = new JsonArray();

                        String[] usersDestiny = destinyAccount.split("_");
                        for (int i = 0; i < usersDestiny.length; i++) {
                            jsonArray.add(usersDestiny[i]);
                        }
                        newPayment.add("destinyAccount", jsonArray);


                        JsonObject objectAccountPaymentDecrypted = secureDocumentLib.unprotect(signedObjectDTOPayment, clientAccount, true, "payment");
                        JsonObject paymentObject = objectAccountPaymentDecrypted.getAsJsonObject("account");

                        String paymentNumbers = paymentObject.getAsJsonPrimitive("payments_number").getAsString();


                        JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, false, "account");

                        String ivAndEncryptedBalanceStr = object.getAsJsonPrimitive("encryptedBalance").getAsString();
                        byte[] ivAndEncryptedBalance = Base64.getDecoder().decode(ivAndEncryptedBalanceStr);

                        // Separate IV and encryptedBalance
                        byte[] iv2 = Arrays.copyOfRange(ivAndEncryptedBalance, 0, 16); // 16 bytes for the IV

                        String encryptedBalance = secureMessageLibDB.protectMessage(secureDocumentLib.encryptBalance(String.valueOf((balance - Double.parseDouble(value))), clientAccount, iv2));
                        outDB.writeUTF(encryptedBalance);
                        writeLogFile("Server", "DataBase", "EncryptedBalance: " + encryptedBalance);

                        String encryptedPaymentNumber = secureMessageLibDB.protectMessage(secureDocumentLib.encryptPaymentNumber(Integer.parseInt(paymentNumbers) + 1, clientAccount, iv));
                        outDB.writeUTF(encryptedPaymentNumber);
                        writeLogFile("Server", "DataBase", "EncryptedPaymentNumber: " + encryptedPaymentNumber);

                        String encryptedPayment = secureMessageLibDB.protectMessage(secureDocumentLib.encryptPayment(newPayment, clientAccount, iv));
                        outDB.writeUTF(encryptedPayment);
                        outDB.flush();
                        writeLogFile("Server", "DataBase", "EncryptedPayment: " + encryptedPayment);

                        String encryptedResultFromDB = inDB.readUTF();
                        String resultFromDB = secureMessageLibDB.unprotectMessage(encryptedResultFromDB);
                        writeLogFile("DataBase", "Server", "EncryptedResultFromDB: " + encryptedResultFromDB
                                    + "DecryptedResultFromDB: " + resultFromDB);

                        return secureMessageLibClient.protectMessage(resultFromDB);
                    } else {
                        outDB.writeUTF(secureMessageLibDB.protectMessage("stop"));
                        return secureMessageLibClient.protectMessage("You dont have balance to make that movement");
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }

        }

    }

    public String handleRequestPayments(String clientAccount) {
        synchronized (outDB){
            synchronized (inDB) {
                try {
                    // Case 0, no update on DB, case 1, new DB update
                    String updateDBFlag = secureMessageLibDB.protectMessage("0");
                    String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
                    String encryptedDocType = secureMessageLibDB.protectMessage("payment");
                    if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed") && !encryptedDocType.equals("Encryption Failed")) {
                        outDB.writeUTF(updateDBFlag);
                        outDB.writeUTF(encryptedAccount);
                        outDB.writeUTF(encryptedDocType);
                        outDB.flush();
                        writeLogFile("Server", "DataBase", "EncryptedUpdateDBFlag: " + updateDBFlag +
                                "\nDecryptedUpdateDBFlag: 1" +
                                "\n----\nEncryptedAccount: " + encryptedAccount +
                                "\nDecryptedAccount: " + clientAccount +
                                "\n----\nencryptedDocType: " + encryptedDocType +
                                "\nDecryptedDocType: payment");

                        String payment = inDB.readUTF();
                        String result = secureMessageLibDB.unprotectMessage(payment);

                        byte[] messageDecoded = Base64.getDecoder().decode(result);

                        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                        SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                        JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "payment");

                        JsonObject accountObject = object.getAsJsonObject("account");

                        writeLogFile("DataBase", "Server", "EncryptedPayment: " + payment +
                                "\nDecryptedPayment: " + accountObject.toString());

                        JsonArray usersArray = accountObject.getAsJsonArray("accountHolder");

                        String sourceAccount = "";

                        for (int i = 0; i < usersArray.size(); i++) {
                            if (i < usersArray.size() - 1){
                                sourceAccount = sourceAccount + usersArray.get(i) + "_";
                            } else {
                                sourceAccount = sourceAccount + usersArray.get(i);
                            }
                        }

                        JsonArray paymentsArray = accountObject.getAsJsonArray("payments");

                        String paymentNumber = accountObject.getAsJsonPrimitive("payments_number").getAsString();

                        String resultMessage = "Total Payments: " + paymentNumber + "\n";

                        for (JsonElement paymentElement : paymentsArray) {
                            JsonObject paymentObject = paymentElement.getAsJsonObject();

                            String date = paymentObject.getAsJsonPrimitive("date").getAsString();
                            double value = paymentObject.getAsJsonPrimitive("value").getAsDouble();
                            String description = paymentObject.getAsJsonPrimitive("description").getAsString();
                            JsonArray users = paymentObject.getAsJsonArray("destinyAccount");

                            String account = "";
                            for (int i = 0; i < users.size(); i++) {
                                if (i != users.size() - 1) {
                                    account = account + users.get(i) + "_";
                                } else {
                                    account = account + users.get(i);
                                }
                            }


                            resultMessage = resultMessage + "Payment\n" + "Source Account: " + sourceAccount + "\nDate: " + date + "\nValue: " + value + "\nDescription: "
                                    + description + "\nDestination Account: " + account  + "\n\n";
                        }
                        return secureMessageLibClient.protectMessage(resultMessage);
                    }
                } catch (Exception e) {
                    return "Error";
                }
                return "Error";
            }
        }
    }

    public String handleRequestPaymentsToConfirm(String user, ConfirmPaymentHandler confirmPaymentHandler) {
        return secureMessageLibClient.protectMessage(confirmPaymentHandler.paymentsToConfirm(user));
    }

    public String handleRequestConfirmPayment(String user, String id,ConfirmPaymentHandler confirmPaymentHandler) {
        if(confirmPaymentHandler.hasID(id)){
            if(confirmPaymentHandler.lastConfirm(user, id)){
                String value = confirmPaymentHandler.getValue(id);
                String destinyAccount = confirmPaymentHandler.getDestinyAccount(id);
                String description = confirmPaymentHandler.getDescription(id);
                String clientsAccount = confirmPaymentHandler.getUsersAccount(id);
                confirmPaymentHandler.remove(id);
                return payment(clientsAccount,value, description, destinyAccount);

            } else {
                return secureMessageLibClient.protectMessage(confirmPaymentHandler.removeUser(id, user));
            }

        } else {
            return secureMessageLibClient.protectMessage("Invalid ID");
        }
    }
}
