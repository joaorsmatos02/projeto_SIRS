package dto;

import java.io.Serializable;
import java.security.SignedObject;
import java.security.cert.Certificate;

public record SignedObjectDTO(SignedObject signedObject, Certificate certificate) implements Serializable {
}
