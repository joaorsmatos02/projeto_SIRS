
import dto.RequestDTO;

import java.util.ArrayList;
import java.util.List;

public class NonceHandler {
    private int counter;
    private List<RequestDTO> requestList = new ArrayList<>();

    public NonceHandler(){
        this.counter = 0;
    }

    public int getNonce(){
        counter ++;
        return counter - 1;
    }

    public void addRequest(int nonce, String request){
        requestList.add(new RequestDTO(nonce, request));
    }

    public boolean validRequest(int nonce, String request){
        if (nonce >= this.counter){
            return false;
        }

        for (int i = 0; i < this.requestList.size(); i++) {
            if (this.requestList.get(i).nonce() == nonce && this.requestList.get(i).request().equals(request)){
                return false;
            }
        }
        return true;
    }
}
