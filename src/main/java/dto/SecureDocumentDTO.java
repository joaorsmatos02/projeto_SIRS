package dto;

import com.google.gson.JsonObject;
import java.io.Serializable;

public record SecureDocumentDTO(String jsonObject, Long timestamp) implements Serializable {
}
