import com.google.gson.JsonObject;
import dto.SignedObjectDTO;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class RequestsHandler {

    public static String handleRequest(SecureMessageLib secureMessageLibDB, SecureMessageLib secureMessageLibClient, SecureDocumentLib secureDocumentLib,ObjectOutputStream outDB, ObjectInputStream inDB, String clientAccount, String accountAlias){
        try {
            // Case 0, no update on DB, case 1, new DB update
            String updateDBFlag = secureMessageLibDB.protectMessage("0");
            String encryptedAccount = secureMessageLibDB.protectMessage(clientAccount);
            if (outDB != null && inDB != null && !encryptedAccount.equals("Encryption Failed") && !updateDBFlag.equals("Encryption Failed")) {
                outDB.writeUTF(updateDBFlag);
                outDB.writeUTF(encryptedAccount);
                outDB.flush();
                String account = inDB.readUTF();
                String result = secureMessageLibDB.unprotectMessage(account);

                byte[] messageDecoded = Base64.getDecoder().decode(result);

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messageDecoded));
                SignedObjectDTO signedObjectDTO = (SignedObjectDTO) ois.readObject();

                JsonObject object = secureDocumentLib.unprotect(signedObjectDTO, clientAccount, true);

                // ir buscar o balance e tratar da resposta

                // encriptar com secureMessageLib

                //e return


            }
        } catch(Exception e) {
            System.err.println("ERRO");
        }


        return "";
    }
}
