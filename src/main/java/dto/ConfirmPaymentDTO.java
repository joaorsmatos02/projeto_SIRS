package dto;

import java.util.List;

public record ConfirmPaymentDTO (int paymentID, List<String> usersToConfirm, String value, String description, String destinyAccount, String clientsAccount) {
}
