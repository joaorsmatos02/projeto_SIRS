package dto;

import com.google.gson.JsonObject;
import java.io.Serializable;

public record SecureDocumentDTO(String document, Long timestamp) implements Serializable {
}
