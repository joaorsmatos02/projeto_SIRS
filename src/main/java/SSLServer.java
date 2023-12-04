import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;

public class SSLServer {

    public static void main(String[] args) throws Exception {
        System.out.println("servidor: main");
        int port = 12345;

        SSLServerSocket serverSocket = null;

        // criar socket
        try {
            System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");

            System.setProperty("javax.net.ssl.keyStore", keyStorePath);
            System.setProperty("javax.net.ssl.keyStorePassword", passwordKeystore);
            serverSocket = (SSLServerSocket) SSLServerSocketFactory.getDefault()
                    .createServerSocket(port);
        } catch (Exception e1) {
            System.out.println("Erro ao inicializar server");
        }

        while (true) {
            SSLSocket socket = (SSLSocket) serverSocket.accept();
            ServerThread st = new ServerThread(socket);
            st.start();
        }
    }
}

class ServerThread extends Thread {

    private SSLSocket socket;

    public ServerThread(SSLSocket inSoc) {
        this.socket = inSoc;
    }

    @Override
    public void run() {

        System.out.println("Cliente conectado");
        ObjectOutputStream out = null;
        ObjectInputStream in = null;

        try {
            // iniciar streams
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
        } catch (Exception e) {
            System.out.println("Cliente desconectado");
        } finally {
            try {
                // fechar ligacoes
                in.close();
                out.close();
                socket.close();
            } catch (IOException e) {
                System.out.println("Ocorreu um erro na comunicacao");
            }
        }
    }
}