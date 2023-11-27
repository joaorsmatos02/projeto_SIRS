package dto;

import com.google.gson.JsonObject;

import java.io.Serializable;

public record TimestampDTO(JsonObject jsonObject, Long timestamp) implements Serializable {

}
