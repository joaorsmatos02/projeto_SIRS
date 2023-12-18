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
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class RequestsHandler {
    private final SecureMessageLib secureMessageLibDB;
    private final SecureMessageLib secureMessageLibClient;
    private final  SecureDocumentLib secureDocumentLib ;
    private final ObjectOutputStream outDB;
    private final ObjectInputStream inDB;

    public RequestsHandler(SecureMessageLib secureMessageLibDB, SecureMessageLib secureMessageLibClient,  SecureDocumentLib secureDocumentLib,ObjectOutputStream outDB, ObjectInputStream inDB){
        this.secureMessageLibDB = secureMessageLibDB;
        this.secureMessageLibClient = secureMessageLibClient;
        this.secureDocumentLib = secureDocumentLib;
        this.outDB = outDB;
        this.inDB = inDB;
    }

    public String handleRequestBalance(String clientAccount){
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
                String account = inDB.readUTF();

                String result = secureMessageLibDB.unprotectMessage(account);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                JsonObject accountObject = object.getAsJsonObject("account");

                double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                String resultMessage = "Your balance is: " + balance + "\n";

                return secureMessageLibClient.protectMessage(resultMessage);

            }
        } catch(Exception e) {
            return "Error";
        }
        return "Error";
    }

    public String handleRequestMovements(String clientAccount){
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

                String account = inDB.readUTF();

                String result = secureMessageLibDB.unprotectMessage(account);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                JsonObject accountObject = object.getAsJsonObject("account");

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
        } catch(Exception e) {
            return "Error";
        }
        return "Error";
    }


    public String handleRequestMakeMovement(String clientAccount, String value, String description) {
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
                movement.addProperty("value", "-"+value);
                movement.addProperty("description", description);

                outDB.writeUTF(updateDBFlag);
                outDB.writeUTF(encryptedAccount);
                outDB.writeUTF(encryptedRequest);
                outDB.flush();

                //get the account to get the iv
                String account = inDB.readUTF();

                String result = secureMessageLibDB.unprotectMessage(account);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject objectAccountDecrypted = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                JsonObject accountObject = objectAccountDecrypted.getAsJsonObject("account");

                double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                if (balance >= Double.parseDouble(value)){
                    outDB.writeUTF(secureMessageLibDB.protectMessage("ok"));

                    JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, false, "account");

                    String ivAndEncryptedBalanceStr = object.getAsJsonPrimitive("encryptedBalance").getAsString();
                    byte[] ivAndEncryptedBalance = Base64.getDecoder().decode(ivAndEncryptedBalanceStr);

                    // Separate IV and encryptedBalance
                    byte[] iv = Arrays.copyOfRange(ivAndEncryptedBalance, 0, 16); // 16 bytes for the IV

                    //outDB.writeUTF(secureMessageLibDB.protectMessage(String.valueOf((balance - Double.parseDouble(value)))));
                    outDB.writeUTF(secureMessageLibDB.protectMessage(secureDocumentLib.encryptBalance(String.valueOf((balance - Double.parseDouble(value))), clientAccount, iv)));
                    outDB.writeUTF(secureMessageLibDB.protectMessage(secureDocumentLib.encryptMovement(movement, clientAccount, iv)));
                    outDB.flush();

                    String resultFromDB = secureMessageLibDB.unprotectMessage(inDB.readUTF());

                    return secureMessageLibClient.protectMessage(resultFromDB);
                } else {
                    outDB.writeUTF(secureMessageLibDB.protectMessage("stop"));
                    return secureMessageLibClient.protectMessage("You dont have balance to make that movement");
                }

            }
        } catch(Exception e) {
            return "Error";
        }
        return "Error";
    }


    public String handleRequestMakePayment(String clientAccount, String value, String description, String destinyAccount){
        try{
            if (clientAccount.split("_").length == 1) {
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

                //get the account to get the iv
                String account = inDB.readUTF();

                String result = secureMessageLibDB.unprotectMessage(account);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject objectAccountDecrypted = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "account");

                JsonObject accountObject = objectAccountDecrypted.getAsJsonObject("account");

                double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();

                if(balance >= Double.parseDouble(value)){
                    outDB.writeUTF(secureMessageLibDB.protectMessage("ok"));
                    outDB.flush();
                    String payment = inDB.readUTF();

                    String paymentResult = secureMessageLibDB.unprotectMessage(payment);

                    byte[] paymentMessageDecoded = Base64.getDecoder().decode(paymentResult);

                    ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(paymentMessageDecoded));
                    SignedObjectDTO signedObjectDTOPayment = (SignedObjectDTO) ois2.readObject();

                    //JsonObject objectAccountPaymentDecrypted = secureDocumentLib.unprotect(signedObjectDTOPayment, clientAccount, true, "payment");
                    JsonObject objectAccountPaymentEncryptedOneLayer = secureDocumentLib.unprotect(signedObjectDTOPayment, clientAccount, false, "payment");

                    String ivAndEncryptedPaymentNumberStr = objectAccountPaymentEncryptedOneLayer.getAsJsonPrimitive("encryptedPaymentNumbers").getAsString();
                    byte[] ivAndEncryptedPaymentNumber = Base64.getDecoder().decode(ivAndEncryptedPaymentNumberStr);

                    // Separate IV and encryptedPaymentNumber
                    byte[] iv = Arrays.copyOfRange(ivAndEncryptedPaymentNumber, 0, 16); // 16 bytes for the IV

                    JsonObject newPayment = new JsonObject();

                    newPayment.addProperty("date", date);
                    newPayment.addProperty("value", "-"+value);
                    newPayment.addProperty("description", description);
                    JsonArray jsonArray = new JsonArray();

                    String [] usersDestiny = destinyAccount.split("_");
                    for (int i = 0; i < usersDestiny.length ; i++) {
                        jsonArray.add(usersDestiny[i]);
                    }
                    newPayment.add("destinyAccount", jsonArray);

                    JsonObject objectAccountPaymentDecrypted = secureDocumentLib.unprotect(signedObjectDTOPayment, clientAccount, true, "payment");
                    String paymentNumbers = objectAccountPaymentDecrypted.getAsJsonPrimitive("encryptedPaymentNumbers").getAsString();


                    JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, false, "account");

                    String ivAndEncryptedBalanceStr = object.getAsJsonPrimitive("encryptedBalance").getAsString();
                    byte[] ivAndEncryptedBalance = Base64.getDecoder().decode(ivAndEncryptedBalanceStr);

                    // Separate IV and encryptedBalance
                    byte[] iv2 = Arrays.copyOfRange(ivAndEncryptedBalance, 0, 16); // 16 bytes for the IV
                    outDB.writeUTF(secureMessageLibDB.protectMessage(secureDocumentLib.encryptBalance(String.valueOf((balance - Double.parseDouble(value))), clientAccount, iv2)));
                    outDB.writeUTF(secureMessageLibDB.protectMessage(secureDocumentLib.encryptPaymentNumber(Integer.parseInt(paymentNumbers) + 1, clientAccount, iv2)));

                    outDB.writeUTF(secureMessageLibDB.protectMessage(secureDocumentLib.encryptPayment(newPayment, clientAccount, iv)));
                    outDB.flush();

                    String resultFromDB = secureMessageLibDB.unprotectMessage(inDB.readUTF());

                    return secureMessageLibClient.protectMessage(resultFromDB);
                } else {
                    outDB.writeUTF(secureMessageLibDB.protectMessage("stop"));
                    return secureMessageLibClient.protectMessage("You dont have balance to make that movement");
                }
            } else {
                //precisa confirmação
                return "aguardando";
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Error";
    }

    public String handleRequestPayments(String clientAccount) {
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

                String payment = inDB.readUTF();

                String result = secureMessageLibDB.unprotectMessage(payment);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true, "payment");

                JsonObject accountObject = object.getAsJsonObject("account");

                JsonArray paymentsArray = accountObject.getAsJsonArray("payments");

                String paymentNumber = accountObject.getAsJsonPrimitive("encryptedPaymentNumbers").getAsString();

                String resultMessage = "Total Payments: " + paymentNumber + "\n";

                for (JsonElement paymentElement : paymentsArray) {
                    JsonObject paymentObject = paymentElement.getAsJsonObject();

                    String date = paymentObject.getAsJsonPrimitive("date").getAsString();
                    double value = paymentObject.getAsJsonPrimitive("value").getAsDouble();
                    String description = paymentObject.getAsJsonPrimitive("description").getAsString();
                    JsonArray users = paymentObject.getAsJsonArray("destinyAccount");

                    String account = "";
                    for (int i = 0; i < users.size(); i++) {
                        if (i != users.size() - 1){
                            account = account + users.get(i) + "_";
                        } else {
                            account = account + users.get(i);
                        }
                    }


                    resultMessage = resultMessage + "Payment\n" + "Date: " + date + "\nValue: " + value + "\nDescription: " + description + "\nDestiny Account: " + account + "\n\n";
                }

                return secureMessageLibClient.protectMessage(resultMessage);
            }
        } catch(Exception e) {
            return "Error";
        }
        return "Error";
    }
}
