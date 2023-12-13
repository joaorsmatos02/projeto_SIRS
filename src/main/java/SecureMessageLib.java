import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;

public class SecureMessageLib {

    private String keyStorePass;
    private String keyStorePath;

    private String trustStorePass;
    private String trustStorePath;
    private String clientAlias;
    private String pkAlias;



    public SecureMessageLib(String keyStorePass, String keyStorePath, String trustStorePass, String trustStorePath, String clientAlias, String pkAlias){
        this.keyStorePass = keyStorePass;
        this.keyStorePath = keyStorePath;
        this.trustStorePass = trustStorePass;
        this.trustStorePath = trustStorePath;
        this.clientAlias = clientAlias;
        this.pkAlias = pkAlias;
    }

    public String protectMessage(String message){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());

            SecretKey secretKeyWithReceiver = (SecretKey) ks.getKey(clientAlias + "_secret", keyStorePass.toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(pkAlias, keyStorePass.toCharArray());
            byte [] encryptedBytes = encrypt(message.getBytes(), secretKeyWithReceiver);

            if(encryptedBytes == null){
                return "Encryption Failed";
            }

            byte [] encryptedBytesSigned = signMessage(encryptedBytes, privateKey);
            return Base64.getEncoder().encodeToString(encryptedBytes) + "|" + Base64.getEncoder().encodeToString(encryptedBytesSigned);
        } catch (Exception e){
             return "Encryption Failed";
        }
    }

    private String decryptMessage(String encryptedMessage) throws Exception {
        try{
            String[] parts = encryptedMessage.split("\\|");

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());

            SecretKey secretKeyWithReceiver = (SecretKey) ks.getKey(clientAlias + "_secret", keyStorePass.toCharArray());

            byte[] encryptedDataWithIV = Base64.getDecoder().decode(parts[0]);
            byte[] signature = Base64.getDecoder().decode(parts[1]);

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(this.trustStorePath);
            trustStore.load(fis, this.trustStorePass.toCharArray());

            Certificate certificate = trustStore.getCertificate(clientAlias + "_cert");
            PublicKey publicKey = certificate.getPublicKey();

            byte[] iv = Arrays.copyOfRange(encryptedDataWithIV, 0, 16);
            byte[] encryptedData = Arrays.copyOfRange(encryptedDataWithIV, iv.length, encryptedDataWithIV.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeyWithReceiver, new IvParameterSpec(iv));
            byte[] decryptedData = cipher.doFinal(encryptedData);

            if(verifySignature(decryptedData, signature, publicKey)){
                return new String(decryptedData);
            } else {
                return "Error verifying signature";
            }
        } catch (Exception e){
            return "Decryption Failed";
        }
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private static byte[] encrypt(byte[] data, SecretKey secretKey) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] ciphered = cipher.doFinal(data);

            byte[] result = new byte[iv.length + ciphered.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphered, 0, result, iv.length, ciphered.length);

            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] signMessage(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
