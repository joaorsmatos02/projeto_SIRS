import dto.ConfirmPaymentDTO;

import java.util.ArrayList;
import java.util.List;

public class ConfirmPaymentHandler {

    public ConfirmPaymentHandler(){
        this.counter = 0;
    }
    private List<ConfirmPaymentDTO> paymentsWaitingForConfirmation = new ArrayList<>();
    private int counter;



    public void addEntry(List<String> usersToConfirm, String value, String description, String destinyAccount) {
        int id = counter;
        counter ++;
        this.paymentsWaitingForConfirmation.add(new ConfirmPaymentDTO(id, usersToConfirm, value, description, destinyAccount));
    }

    public String paymentsToConfirm(String user) {
        String result = "Your Payments waiting for confirmation:\n";
        boolean isEmpty = true;
        for (ConfirmPaymentDTO payment : this.paymentsWaitingForConfirmation){
            if (payment.usersToConfirm().contains(user)){
                result = result + "Payment ID: " + payment.paymentID() + "\nValue: " + payment.value()
                        + "\nDestination account: " + payment.destinyAccount()
                        + "\nDescription: " + payment.description() + "\n\n";
                isEmpty = false;
            }
        }

        if(isEmpty) {
            return "You dont have any pending payments.";
        }
        return result;
    }

    public boolean hasID(String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                return true;
            }
        }
        return false;
    }

    public boolean lastConfirm(String user, String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id) && paymentsWaitingForConfirmation.get(i).usersToConfirm().size() == 1 ){
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    public String getValue(String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                return paymentsWaitingForConfirmation.get(i).value();
            }
        }
        return null;
    }

    public String getDestinyAccount(String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                return paymentsWaitingForConfirmation.get(i).destinyAccount();
            }
        }
        return null;
    }

    public String getDescription(String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                return paymentsWaitingForConfirmation.get(i).description();
            }
        }
        return null;
    }

    public String removeUser(String id, String user) {
        String result = "Waiting for ";
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if(paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                for (int j = 0; j < paymentsWaitingForConfirmation.get(i).usersToConfirm().size(); j++) {
                    if (paymentsWaitingForConfirmation.get(i).usersToConfirm().get(j).equals(user)){
                        paymentsWaitingForConfirmation.get(i).usersToConfirm().remove(j);
                        break;
                    }
                }
                for (int j = 0; j < paymentsWaitingForConfirmation.get(i).usersToConfirm().size(); j++) {
                    if (j < paymentsWaitingForConfirmation.get(i).usersToConfirm().size() - 1){
                        result = result + paymentsWaitingForConfirmation.get(i).usersToConfirm().get(i) + " and ";
                    } else {
                        result = result + paymentsWaitingForConfirmation.get(i).usersToConfirm().get(i) + "\n";
                    }
                }

            }
        }
        return result;
    }

    public void remove(String id) {
        for (int i = 0; i < paymentsWaitingForConfirmation.size(); i++) {
            if (paymentsWaitingForConfirmation.get(i).paymentID() == Integer.parseInt(id)){
                paymentsWaitingForConfirmation.remove(i);
                break;
            }
        }
    }
}
