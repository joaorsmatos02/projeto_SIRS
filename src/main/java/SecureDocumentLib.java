import com.google.gson.*;
import dto.SecureDocumentDTO;
import dto.SignedObjectDTO;
import utils.RequestTable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigDecimal;
import java.security.*;
import java.security.cert.Certificate;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
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

            SignedObject signed = signJSONTimestamp(new SecureDocumentDTO(encryptedJson.toString(), timestamp), privateKey);
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


        // Generate a random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // Encrypt balance, currency, and movements
        double balance = encryptedJson.getAsJsonPrimitive("balance").getAsDouble();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Encrypt balance
        byte[] encryptedBalance = cipher.doFinal(Double.toString(balance).getBytes());
        // Concatenate IV and encryptedBalance
        byte[] ivAndEncryptedBalance = new byte[iv.length + encryptedBalance.length];
        System.arraycopy(iv, 0, ivAndEncryptedBalance, 0, iv.length);
        System.arraycopy(encryptedBalance, 0, ivAndEncryptedBalance, iv.length, encryptedBalance.length);
        encryptedJson.add("encryptedBalance", new JsonPrimitive(Base64.getEncoder().encodeToString(ivAndEncryptedBalance)));
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
        JsonObject decryptedJson = new JsonObject();
        JsonArray accountHolderArray = encryptedJson.getAsJsonArray("accountHolder");

        decryptedJson.add("accountHolder", accountHolderArray);

        // Retrieve the IV and encrypted data from the JSON file
        String ivAndEncryptedBalanceStr = encryptedJson.getAsJsonPrimitive("encryptedBalance").getAsString();
        byte[] ivAndEncryptedBalance = Base64.getDecoder().decode(ivAndEncryptedBalanceStr);

        // Separate IV and encryptedBalance
        byte[] iv = Arrays.copyOfRange(ivAndEncryptedBalance, 0, 16); // 16 bytes for the IV
        byte[] encryptedBalance = Arrays.copyOfRange(ivAndEncryptedBalance, iv.length, ivAndEncryptedBalance.length);

        // Decrypt balance, currency, and movements
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Decrypt balance
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedBalance = cipher.doFinal(encryptedBalance);
        double balance = Double.parseDouble(new String(decryptedBalance));
        decryptedJson.addProperty("balance", balance);


        // Decrypt currency
        String encryptedCurrencyStr = encryptedJson.getAsJsonPrimitive("encryptedCurrency").getAsString();
        byte[] encryptedCurrency = Base64.getDecoder().decode(encryptedCurrencyStr);
        String currency = new String(cipher.doFinal(encryptedCurrency));
        decryptedJson.addProperty("currency", currency);

        // Decrypt movements
        JsonArray movementsArray = encryptedJson.getAsJsonArray("movements");
        JsonArray movementsArrayCopy = new JsonArray();
        for (JsonElement j : movementsArray) {
            JsonObject movement = j.getAsJsonObject();

            // Decrypt movement date
            String encryptedDateStr = movement.getAsJsonPrimitive("encryptedDate").getAsString();
            byte[] encryptedDate = Base64.getDecoder().decode(encryptedDateStr);
            String decryptedDateStr = new String(cipher.doFinal(encryptedDate));
            SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy"); //Error if not formatted like this
            Date date = dateFormat.parse(decryptedDateStr);

            SimpleDateFormat wellFormattedDate = new SimpleDateFormat("dd/MM/yyyy");
            String wellFormattedStr = wellFormattedDate.format(date);
            Date dateWellFormatted = wellFormattedDate.parse(wellFormattedStr);

            movement.addProperty("date", wellFormattedDate.format(dateWellFormatted));
            movement.remove("encryptedDate");

            // Decrypt movement value
            String encryptedValueStr = movement.getAsJsonPrimitive("encryptedValue").getAsString();
            byte[] encryptedValue = Base64.getDecoder().decode(encryptedValueStr);
            double value = Double.parseDouble(new String(cipher.doFinal(encryptedValue)));
            // Format the double value to always have two decimal places
            String formattedValue = String.format("%.2f", value);
            // Use BigDecimal to preserve precision
            BigDecimal bigDecimalValue = new BigDecimal(formattedValue);
            movement.addProperty("value", bigDecimalValue);
            movement.remove("encryptedValue");

            // Decrypt movement description
            String encryptedDescriptionStr = movement.getAsJsonPrimitive("encryptedDescription").getAsString();
            byte[] encryptedDescription = Base64.getDecoder().decode(encryptedDescriptionStr);
            String description = new String(cipher.doFinal(encryptedDescription));
            movement.addProperty("description", description);
            movement.remove("encryptedDescription");

            movementsArrayCopy.add(movement);
        }

        decryptedJson.add("movements", movementsArrayCopy);

        JsonObject result = new JsonObject();
        result.add("account", decryptedJson);
        return result;
    }

    //------------------------------------------------------------------------------------------------------------------

    private static void writeToFile(File file, Object... objects) {
        for (Object o : objects) {
            if (o instanceof JsonObject) {
                writeObjectStr(file, o.toString());
            } else {
                writeObject(file, o);
            }
        }

    }

    private static void writeObjectStr(File file, String object) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeObject(File file, Object object) {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file))) {
            objectOutputStream.writeObject(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}