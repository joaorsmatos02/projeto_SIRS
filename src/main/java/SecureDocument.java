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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class SecureDocument {

    public void protect(String filename, SecretKey secretKey, PrivateKey privateKey) {
        try (FileReader fileReader = new FileReader(filename)) {

            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class); // cifrar com secretkey

            // gerar timestamp

            // assinar tuplo (json_encriptado, timestamp) com a privateKey

            // escrever tuplo (jsonjson_encriptado, timestamp, assinatura) num ficheiro
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean check(String filename, SecretKey secretKey, PublicKey publicKey) {

    }

    public void unprotect(String filename, SecretKey secretKey) {

    }

    ////////////////////////////////////////////////////////////////////////////

    public void protectDB(String filename, SecretKey secretKey, PrivateKey privateKey) throws Exception {
        try (FileReader fileReader = new FileReader(filename)) {
            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);

            // Encrypt sensitive data
            encryptSensitiveData(rootJson, secretKey);

            // Save the encrypted JSON to a new file
            try (FileWriter fileWriter = new FileWriter("encrypted_" + filename)) {
                gson.toJson(rootJson, fileWriter);
            }
        }
    }

    private void encryptSensitiveData(JsonObject rootJson, SecretKey secretKey) throws Exception {
        // Extract and encrypt account information
        JsonObject accountObject = rootJson.getAsJsonObject("account");
        JsonArray accountHolderArray = accountObject.getAsJsonArray("accountHolder");

        // Encrypt balance, currency, and movements
        double balance = accountObject.getAsJsonPrimitive("balance").getAsDouble();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt balance
        byte[] encryptedBalance = cipher.doFinal(Double.toString(balance).getBytes());
        accountObject.add("encryptedBalance", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedBalance)));

        // Encrypt currency
        String currency = accountObject.getAsJsonPrimitive("currency").getAsString();
        byte[] encryptedCurrency = cipher.doFinal(currency.getBytes());
        accountObject.add("encryptedCurrency", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedCurrency)));

        // Encrypt movements
        JsonArray movementsArray = accountObject.getAsJsonArray("movements");
        for (int i = 0; i < movementsArray.size(); i++) {
            JsonObject movement = movementsArray.get(i).getAsJsonObject();

            // Encrypt movement value
            double value = movement.getAsJsonPrimitive("value").getAsDouble();
            byte[] encryptedValue = cipher.doFinal(Double.toString(value).getBytes());
            movement.add("encryptedValue", new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedValue)));
        }
    }

}