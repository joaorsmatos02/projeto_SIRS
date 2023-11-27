import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Welcome to BlingBank!");
        printHelp();
        String line = "";

        while (!(line = sc.nextLine()).equals("exit")) {
            String[] command = line.split(" ");
            if(command[0].equals("BlingBank")) {
                switch(command[1]) {
                    case "help":
                        printHelp();
                        break;
                    case "protect":
                        try {
                            prepareProtect(command);
                        } catch (Exception e) {
                            printInvalidArguments("protect");
                        }
                        break;
                    case "check":
                        try {
                            prepareCheck(command);
                        } catch (Exception e) {
                            printInvalidArguments("check");
                        }
                        break;
                    case "unprotect":
                        try {
                            prepareUnprotect(command);
                        } catch (Exception e) {
                            printInvalidArguments("unprotect");
                        }
                        break;
                    default:
                        System.out.println("Unknown command. Use 'BlingBank help' to see the list of available commands.");                }
            } else {
                System.out.println("All requests should start with \"BlingBank\"");
            }
        }
    }

    private static void printHelp() {
        System.out.println("""
                BlingBank help
                Displays help information for all available commands.

                BlingBank protect (inputFile) (outputFile) (clientID)
                Encrypts sensitive data in the specified file and writes the result.
                Arguments:
                   - (inputFile): Path to the input file.
                   - (outputFile): Path to the output file.
                   - (clientID): Client ID.
                BlingBank check (inputFile)
                Checks the integrity of the specified file containing protected data.
                Arguments:
                   - (inputFile): Path to the input file.

                BlingBank unprotect (inputFile) (outputFile) (clientID)
                Decrypts the protected data in the specified file and writes the result.
                Arguments:
                   - (inputFile): Path to the input file.
                   - (outputFile): Path to the output file.
                   - (clientID): Client ID.""");
    }

    private static void prepareProtect(String[] args) throws Exception {
        if(args.length != 7) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
            return;
        }

        File outputFile = new File(args[3]);
        if(outputFile.exists()) {
            System.out.println("Output file already exists");
            return;
        }

        FileInputStream is = new FileInputStream(args[4]);
        String passwordKeyStore = args[5];
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(is, passwordKeyStore.toCharArray());

        SecretKey secretKey = (SecretKey) keyStore.getKey("secret_key", args[6].toCharArray());
        Certificate certificate = keyStore.getCertificate("certificate");
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("private_key", passwordKeyStore.toCharArray());


        SecureDocumentLib.protect(inputFile, outputFile, secretKey, privateKey, certificate);
    }

    private static void prepareCheck(String[] args) throws Exception{
        if(args.length != 3) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
        }

        SecureDocumentLib.check(inputFile);
    }

    private static void prepareUnprotect(String[] args) throws Exception{
        if(args.length != 7) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
            return;
        }

        File outputFile = new File(args[3]);
        if(outputFile.exists()) {
            System.out.println("Output file already exists");
            return;
        }

        FileInputStream is = new FileInputStream(args[4]);
        String passwordKeyStore = args[5];
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(is, passwordKeyStore.toCharArray());

        SecretKey secretKey = (SecretKey) keyStore.getKey("secret_key", args[6].toCharArray());

        SecureDocumentLib.unprotect(inputFile, outputFile, secretKey);
    }

    private static void printInvalidArguments(String command) {
        switch (command) {
            case "protect":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("Usage: BlingBank protect (inputFile) (outputFile) (clientID)");
                break;
            case "check":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("Usage: BlingBank check (inputFile)");
                break;
            case "unprotect":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("Usage: BlingBank unprotect (inputFile) (outputFile) (clientID)");
                break;
        }
    }

}
