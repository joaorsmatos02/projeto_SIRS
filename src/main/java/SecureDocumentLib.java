import com.google.gson.*;
import dto.SecureDocumentDTO;
import dto.SignedObjectDTO;
import utils.RequestTable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class SecureDocumentLib {

    private static final long EXPIRATION_TIME_MILLIS = 1120000;


    public static void protect(File inputFile, File outputFile, SecretKey secretKey, PrivateKey privateKey, Certificate certificate) {
        try (FileReader fileReader = new FileReader(inputFile)) {

            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
            JsonObject encryptedJson = encryptSensitiveData(rootJson, secretKey);

            long timestamp = System.currentTimeMillis();

            SignedObject signed = signJSONTimestamp(new SecureDocumentDTO(encryptedJson.toString(),timestamp), privateKey);
            writeToFile(outputFile, new SignedObjectDTO(signed, certificate));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static JsonObject encryptSensitiveData(JsonObject rootJson, SecretKey secretKey) throws Exception {
        // Extract and encrypt account information
        JsonObject encryptedJson = rootJson.getAsJsonObject("account");
        JsonArray accountHolderArray = encryptedJson.getAsJsonArray("accountHolder");

        encryptedJson.add("accountHolder", accountHolderArray);

        // Encrypt balance, currency, and movements
        double balance = encryptedJson.getAsJsonPrimitive("balance").getAsDouble();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt balance
        byte[] encryptedBalance = cipher.doFinal(Double.toString(balance).getBytes());
        encryptedJson.add("encryptedBalance", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedBalance)));
        encryptedJson.remove("balance");

        // Encrypt currency
        String currency = encryptedJson.getAsJsonPrimitive("currency").getAsString();
        byte[] encryptedCurrency = cipher.doFinal(currency.getBytes());
        encryptedJson.add("encryptedCurrency", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedCurrency)));
        encryptedJson.remove("currency");

        // Encrypt movements
        JsonArray movementsArray = encryptedJson.getAsJsonArray("movements");
        for (JsonElement j : movementsArray) {
            JsonObject movement = j.getAsJsonObject();

            // Encrypt movement value
            double value = movement.getAsJsonPrimitive("value").getAsDouble();
            byte[] encryptedValue = cipher.doFinal(Double.toString(value).getBytes());
            movement.add("encryptedValue", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedValue)));
            movement.remove("value");

            // Encrypt movement date
            // Adapt "date" to Date type
            String dateString = movement.getAsJsonPrimitive("date").getAsString();
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
            Date date = dateFormat.parse(dateString);
            byte[] encryptedDate = cipher.doFinal(date.toString().getBytes());
            movement.add("encryptedDate", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedDate)));
            movement.remove("date");

            // Encrypt movement description
            String description = movement.getAsJsonPrimitive("description").getAsString();
            byte[] encryptedDescription = cipher.doFinal(description.getBytes());
            movement.add("encryptedDescription", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedDescription)));
            movement.remove("description");
        }

        return encryptedJson;
    }

    private static SignedObject signJSONTimestamp(SecureDocumentDTO jsonTimestampDTO, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            return new SignedObject(jsonTimestampDTO, privateKey, signature);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    //------------------------------------------------------------------------------------------------------------------

    public static boolean check(File file) {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(file))) {

            Signature signature = Signature.getInstance("SHA256withRSA");

            SignedObjectDTO signedObjectDTO = (SignedObjectDTO) objectInputStream.readObject();
            SignedObject signedObject = signedObjectDTO.signedObject();
            Certificate certificate = signedObjectDTO.certificate();

            if (signedObject.verify(certificate.getPublicKey(), signature)) {
                SecureDocumentDTO document = (SecureDocumentDTO) signedObject.getObject();
                return verifyTimestamp(document);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private static boolean verifyTimestamp(SecureDocumentDTO dto) {
        return System.currentTimeMillis() - dto.timestamp() <= EXPIRATION_TIME_MILLIS &&
                !RequestTable.hasEntry(JsonParser.parseString(dto.jsonObject()).getAsJsonObject());
    }

    //------------------------------------------------------------------------------------------------------------------

    public static void unprotect(File inputFile, File outputFile, SecretKey secretKey) {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(inputFile))) {

            SignedObjectDTO signedObjectDTO = (SignedObjectDTO) objectInputStream.readObject();
            SecureDocumentDTO dto = (SecureDocumentDTO) signedObjectDTO.signedObject().getObject();
            JsonObject document = JsonParser.parseString(dto.jsonObject()).getAsJsonObject();
            writeToFile(outputFile, decryptSensitiveData(document, secretKey));

            RequestTable.addEntry(document); // TODO

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static JsonObject decryptSensitiveData(JsonObject encryptedJson, SecretKey secretKey) throws Exception {
         // Extract and decrypt account information
        JsonObject decryptedJson = encryptedJson.getAsJsonObject("account");
        JsonArray accountHolderArray = decryptedJson.getAsJsonArray("accountHolder");

        decryptedJson.add("accountHolder", accountHolderArray);

        // Decrypt balance, currency, and movements
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decrypt balance
        String encryptedBalanceStr = encryptedJson.getAsJsonPrimitive("encryptedBalance").getAsString();
        byte[] encryptedBalance = Base64.getDecoder().decode(encryptedBalanceStr);
        double balance = Double.parseDouble(new String(cipher.doFinal(encryptedBalance)));
        decryptedJson.addProperty("balance", balance);

        // Decrypt currency
        String encryptedCurrencyStr = encryptedJson.getAsJsonPrimitive("encryptedCurrency").getAsString();
        byte[] encryptedCurrency = Base64.getDecoder().decode(encryptedCurrencyStr);
        String currency = new String(cipher.doFinal(encryptedCurrency));
        decryptedJson.addProperty("currency", currency);

        // Decrypt movements
        JsonArray movementsArray = decryptedJson.getAsJsonArray("movements");
        for (JsonElement j : movementsArray) {
            JsonObject movement = j.getAsJsonObject();

            // Decrypt movement value
            String encryptedValueStr = movement.getAsJsonPrimitive("encryptedValue").getAsString();
            byte[] encryptedValue = Base64.getDecoder().decode(encryptedValueStr);
            double value = Double.parseDouble(new String(cipher.doFinal(encryptedValue)));
            movement.addProperty("value", value);

            // Decrypt movement date
            String encryptedDateStr = movement.getAsJsonPrimitive("encryptedDate").getAsString();
            byte[] encryptedDate = Base64.getDecoder().decode(encryptedDateStr);
            String decryptedDateStr = new String(cipher.doFinal(encryptedDate));
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
            Date date = dateFormat.parse(decryptedDateStr);
            movement.addProperty("date", dateFormat.format(date)); // Assuming you want to keep it as a formatted string

            // Decrypt movement description
            String encryptedDescriptionStr = movement.getAsJsonPrimitive("encryptedDescription").getAsString();
            byte[] encryptedDescription = Base64.getDecoder().decode(encryptedDescriptionStr);
            String description = new String(cipher.doFinal(encryptedDescription));
            movement.addProperty("description", description);
        }

        return decryptedJson;
    }

    //------------------------------------------------------------------------------------------------------------------

    private static void writeToFile(File file, Object... objects) {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file))) {
            for (Object o : objects) {
                objectOutputStream.writeObject(o);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}