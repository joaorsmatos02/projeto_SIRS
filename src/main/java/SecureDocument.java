import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

public class SecureDocument {

    public void protect(String filename, SecretKey secretKey, PrivateKey privateKey) {
        try (FileReader fileReader = new FileReader(filename)) {

            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);

            JsonObject encryptedJson = encryptSensitiveData(rootJson, secretKey);

            long timestamp = System.currentTimeMillis();

             HashMap<JsonObject, Long> jsonTimestampMap = new HashMap<>();
             jsonTimestampMap.put(encryptedJson, timestamp);

            // Sign the map (encrypted_json, timestamp) with privateKey
            String signature = signJsonTimestamp(jsonTimestampMap, privateKey);

            // Write the map (encrypted_json, timestamp) to the file
            writeToFile(encryptedJson, timestamp, signature, "encrypted_" + filename);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean check(String filename, SecretKey secretKey, PublicKey publicKey) {
        return true;
    }

    public void unprotect(String filename, SecretKey secretKey) {

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
        for (int i = 0; i < movementsArray.size(); i++) {
            JsonObject movement = movementsArray.get(i).getAsJsonObject();

            // Encrypt movement value
            double value = movement.getAsJsonPrimitive("value").getAsDouble();
            byte[] encryptedValue = cipher.doFinal(Double.toString(value).getBytes());
            movement.add("encryptedValue", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedValue)));
        }

        return encryptedJson;
    }

    private String signJsonTimestamp(HashMap<JsonObject, Long> jsonTimestampMap, PrivateKey privateKey) {
        // Convert the map to a JSON string
        Gson gson = new Gson();
        String jsonString = gson.toJson(jsonTimestampMap);

        try {
            // Get a signature instance
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);

            // Update the signature with the JSON string
            signature.update(jsonString.getBytes());

            // Sign the data
            byte[] signatureBytes = signature.sign();

            //  - verificar este return - Encode the signature as a base64 string
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            // Handle exceptions appropriately in your code
            return null;
        }
    }

    private static void writeToFile(JsonObject encryptedJson, long timestamp, String signature, String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            // Create a new JSON object to hold the data (encrypted_json, timestamp, signature)
            JsonObject dataToWrite = new JsonObject();
            dataToWrite.add("encrypted_json", encryptedJson);
            dataToWrite.addProperty("timestamp", timestamp);
            dataToWrite.addProperty("signature", signature);

            // Convert the JSON object to a string and write it to the file
            Gson gson = new Gson();
            String jsonString = gson.toJson(dataToWrite);
            writer.write(jsonString);
        } catch (IOException e) {
            e.printStackTrace();
            // Handle the exception appropriately for your application
        }
    }

}