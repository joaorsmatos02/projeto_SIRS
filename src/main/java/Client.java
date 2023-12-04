import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class Client {

    private static SSLSocket socket;
    private static String name;

    public static void main(String[] args) {
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("javax.net.ssl.trustStore", truststore);
        System.setProperty("javax.net.ssl.trustStorePassword", "123456");

        FileInputStream truststorefile = new FileInputStream(truststore);
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(truststorefile, "123456".toCharArray());

        FileInputStream keystorefile = new FileInputStream(keystore);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keystorefile, passwordKeystore.toCharArray());
        Certificate cert = keyStore.getCertificate(name + "_key"); // extrair o proprio certificado
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(name + "_key", passwordKeystore.toCharArray());

        // estabelecer ligacao
        socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(localhost, 12345);

        // iniciar streams
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        //ações


        // fechar ligacoes
        in.close();
        out.close();
        socket.close();
        keystorefile.close();
        truststorefile.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}
