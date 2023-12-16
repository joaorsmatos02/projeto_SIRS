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
            if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed")) {
                outDB.writeUTF(updateDBFlag);
                outDB.writeUTF(encryptedAccount);
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
            if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed")) {
                outDB.writeUTF(updateDBFlag);
                outDB.writeUTF(encryptedAccount);
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
        if (clientAccount.split("_").length > 1){
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
            Date currentDate = new Date();
            String date = dateFormat.format(currentDate);

            JsonObject payment = new JsonObject();

            payment.addProperty("date", date);
            payment.addProperty("value", "-"+value);
            payment.addProperty("description", description);



            // criar array e meter no payment, obter conta dos payments, obter iv e encriptar payment, obter a conta e verificar o balance, alterar balance enviar encriptado


            return "ok";
        } else {
            //precisa confirmação
            return "aguardando";
        }
    }
}
