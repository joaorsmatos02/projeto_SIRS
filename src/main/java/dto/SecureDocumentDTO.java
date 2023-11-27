package dto;

import com.google.gson.JsonObject;

import java.io.Serializable;

public record SecureDocumentDTO(JsonObject jsonObject, Long timestamp) implements Serializable {

}
