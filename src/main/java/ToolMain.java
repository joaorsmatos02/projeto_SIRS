import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dto.SignedObjectDTO;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Scanner;

import static utils.utils.writeToFile;

public class ToolMain {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("""
                Welcome to BlingBank!
                Available commands:
                 - BlingBank protect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)
                 - BlingBank check (inputFile)
                 - BlingBank unprotect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)
                 
                 If necessary, use 'BlingBank help' to see more details about each command.
                 
                 Insert command: """);

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
                            System.out.println(prepareCheck(command));
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
                        System.out.println("Unknown command. Use 'BlingBank help' to see the list of available commands.");
                }
                System.out.print("Insert command:");
            } else {
                System.out.println("All requests should start with \"BlingBank\".");
                System.out.print("Insert command: ");
            }
        }
        sc.close();
    }

    private static void printHelp() {
        System.out.println("""
                BlingBank help
                Displays help information for all available commands.

                BlingBank protect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)
                Encrypts sensitive data in the specified file and writes the result.
                Arguments:
                   - (inputFile): Path to the input file.
                   - (outputFile): Path to the output file.
                   - (accountAlias): Account Name that is being used. (e.g. "alice", or to shared accounts: "alice_bob")
                   - (flagTwoLayerEncryption): If this flag is set, the sensitive fields of the JSON document will be encrypted individually, before a full encryption of the document, this is used when sending files from the server to the database, so the latter can verify the identity of the server but not access the values.
                   - (keyStoreName): KeyStore name > Two options only: KeyStore Name from the Server or from the DataBase Server.
                   - (keyStorePass) KeyStore Password > Two options only: KeyStore Password from the Server or from the DataBase Server.
                   - (keyStorePath) KeyStore Path > Two options only: KeyStore Path from the Server or from the DataBase Server.
                   
                BlingBank check (inputFile)
                Checks the integrity of the specified file containing protected data.
                Arguments:
                   - (inputFile): Path to the input file.

                BlingBank unprotect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)
                Decrypts the protected data in the specified file and writes the result.
                Arguments:
                   - (inputFile): Path to the input file.
                   - (outputFile): Path to the output file.
                   - (accountAlias): Account Name that is being used. (e.g. "alice", or to shared accounts: "alice_bob")
                   - (flagTwoLayerEncryption): If this flag is set, the full document will be decrypted before the sensitive fields of the JSON document will be decrypted individually.
                   - (keyStoreName): KeyStore name > Two options only: KeyStore Name from the Server or from the DataBase Server.
                   - (keyStorePass) KeyStore Password > Two options only: KeyStore Password from the Server or from the DataBase Server.
                   - (keyStorePath) KeyStore Path > Two options only: KeyStore Path from the Server or from the DataBase Server.""");


        System.out.print("Insert command: ");

    }

    private static void prepareProtect(String[] args) throws Exception {
        if(args.length != 9) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
            return;
        }
        Gson gson = new Gson();
        FileReader fileReader = new FileReader(inputFile);
        JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);

        File outputFile = new File(args[3]);
        if(outputFile.exists()) {
            System.out.println("Output file already exists");
            return;
        }

        String userAccount = args[4];
        boolean flagTwoLayerEncryption = "1".equals(args[5]);

        String KeyStoreName = args[6];
        String keyStorePass = args[7];
        String keyStorePath = args[8];

        SecureDocumentLib secureDocLib = new SecureDocumentLib(KeyStoreName, keyStorePass, keyStorePath);
        writeToFile(outputFile, secureDocLib.protect(rootJson, userAccount, flagTwoLayerEncryption));
    }

    private static boolean prepareCheck(String[] args) {
        if(args.length != 3) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
        }

        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(inputFile));
            SignedObjectDTO signedObjectDTO = (SignedObjectDTO) objectInputStream.readObject();
            return SecureDocumentLib.check(signedObjectDTO);
        } catch (Exception e) {
            return false;
        }

    }

    private static void prepareUnprotect(String[] args) throws Exception{
        if(args.length != 9) {
            throw new IllegalArgumentException();
        }

        File inputFile = new File(args[2]);
        if(!inputFile.exists()) {
            System.out.println("Input file not found");
            return;
        }
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(inputFile));
        SignedObjectDTO signedObjectDTO = (SignedObjectDTO) objectInputStream.readObject();


        File outputFile = new File(args[3]);
        if(outputFile.exists()) {
            System.out.println("Output file already exists");
            return;
        }

        String userAccount = args[4];
        boolean flagTwoLayerEncryption = "1".equals(args[5]);

        String KeyStoreName = args[6];
        String keyStorePass = args[7];
        String keyStorePath = args[8];

        SecureDocumentLib secureDocLib = new SecureDocumentLib(KeyStoreName, keyStorePass, keyStorePath);
        writeToFile(outputFile, secureDocLib.unprotect(signedObjectDTO, userAccount, flagTwoLayerEncryption));

    }

    private static void printInvalidArguments(String command) {
        switch (command) {
            case "protect":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("Usage: BlingBank protect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)");
                System.out.print("Insert command: ");
                break;
            case "check":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("Usage: BlingBank check (inputFile)");
                System.out.print("Insert command: ");
                break;
            case "unprotect":
                System.out.println("Invalid arguments for command: " + command);
                System.out.println("BlingBank unprotect (inputFile) (outputFile) (accountAlias) (flagTwoLayerEncryption) (keyStoreName) (keyStorePass) (keyStorePath)");
                System.out.print("Insert command: ");
                break;
        }
    }

}
