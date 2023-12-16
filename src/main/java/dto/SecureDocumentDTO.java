package dto;

import java.io.Serializable;

public record SecureDocumentDTO(String document, Long timestamp) implements Serializable {
}
