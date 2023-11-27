import com.google.gson.*;
import dto.TimestampDTO;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class SecureDocument {

    public void protect(String filename, SecretKey secretKey, PrivateKey privateKey) {
        try (FileReader fileReader = new FileReader(filename)) {

            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
            JsonObject encryptedJson = encryptSensitiveData(rootJson, secretKey);

            long timestamp = System.currentTimeMillis();

            SignedObject signed = signJSONTimestamp(new TimestampDTO(encryptedJson,timestamp), privateKey);
            writeToFile("encrypted_" + filename, signed);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private JsonObject encryptSensitiveData(JsonObject rootJson, SecretKey secretKey) throws Exception {
        // Extract and encrypt account information
        JsonObject encryptedJson = rootJson.getAsJsonObject("account");
        JsonArray accountHolderArray = encryptedJson.getAsJsonArray("accountHolder");

        // Encrypt balance, currency, and movements
        double balance = encryptedJson.getAsJsonPrimitive("balance").getAsDouble();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt balance
        byte[] encryptedBalance = cipher.doFinal(Double.toString(balance).getBytes());
        encryptedJson.add("encryptedBalance", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedBalance)));

        // Encrypt currency
        String currency = encryptedJson.getAsJsonPrimitive("currency").getAsString();
        byte[] encryptedCurrency = cipher.doFinal(currency.getBytes());
        encryptedJson.add("encryptedCurrency", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedCurrency)));

        // Encrypt movements
        JsonArray movementsArray = encryptedJson.getAsJsonArray("movements");
        for (JsonElement j : movementsArray) {
            JsonObject movement = j.getAsJsonObject();

            // Encrypt movement value
            double value = movement.getAsJsonPrimitive("value").getAsDouble();
            byte[] encryptedValue = cipher.doFinal(Double.toString(value).getBytes());
            movement.add("encryptedValue", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedValue)));
        }

        return encryptedJson;
    }

    private SignedObject signJSONTimestamp(TimestampDTO jsonTimestampDTO, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            return new SignedObject(jsonTimestampDTO, privateKey, signature);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    //------------------------------------------------------------------------------------------------------------------

    public boolean check(String filename, PublicKey publicKey) {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(filename))) {

            SignedObject signedObject = (SignedObject) objectInputStream.readObject();
            Signature signature = Signature.getInstance("SHA256withRSA");

            if (signedObject.verify(publicKey, signature)) {
                TimestampDTO content = (TimestampDTO) signedObject.getObject();
                return verifyTimestamp(content.timestamp());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean verifyTimestamp(Long timestamp) {
        return System.currentTimeMillis() - timestamp <= 60000;
    }

    //------------------------------------------------------------------------------------------------------------------

    public void unprotect(String filename, SecretKey secretKey) {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(filename))) {

            SignedObject signedObject = (SignedObject) objectInputStream.readObject();
            TimestampDTO dto = (TimestampDTO) signedObject.getObject();
            writeToFile(filename + "_decrypted", decryptSensitiveData(dto.jsonObject(), secretKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private JsonObject decryptSensitiveData(JsonObject encryptedJson, SecretKey secretKey) throws Exception {
        // Extract encrypted information

        JsonArray accountHolderArray = encryptedJson.getAsJsonArray("accountHolder");

        // Decrypt balance, currency, and movements
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decrypt balance
        String encryptedBalanceBase64 = encryptedJson.getAsJsonPrimitive("encryptedBalance").getAsString();
        byte[] encryptedBalance = Base64.getDecoder().decode(encryptedBalanceBase64);
        double balance = Double.parseDouble(new String(cipher.doFinal(encryptedBalance)));

        // Decrypt currency
        String encryptedCurrencyBase64 = encryptedJson.getAsJsonPrimitive("encryptedCurrency").getAsString();
        byte[] encryptedCurrency = Base64.getDecoder().decode(encryptedCurrencyBase64);
        String currency = new String(cipher.doFinal(encryptedCurrency));

        // Decrypt movements
        JsonArray movementsArray = encryptedJson.getAsJsonArray("movements");
        for (int i = 0; i < movementsArray.size(); i++) {
            JsonObject movement = movementsArray.get(i).getAsJsonObject();

            // Decrypt movement value
            String encryptedValueBase64 = movement.getAsJsonPrimitive("encryptedValue").getAsString();
            byte[] encryptedValue = Base64.getDecoder().decode(encryptedValueBase64);
            double value = Double.parseDouble(new String(cipher.doFinal(encryptedValue)));
            movement.addProperty("value", value);
        }

        JsonObject decryptedJson = new JsonObject();
        decryptedJson.add("accountHolder", accountHolderArray);
        decryptedJson.addProperty("balance", balance);
        decryptedJson.addProperty("currency", currency);
        decryptedJson.add("movements", movementsArray);

        return decryptedJson;
    }

    //------------------------------------------------------------------------------------------------------------------

    private static void writeToFile(String filename, Object... objects) {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(filename))) {
            for (Object o : objects) {
                objectOutputStream.writeObject(o);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}