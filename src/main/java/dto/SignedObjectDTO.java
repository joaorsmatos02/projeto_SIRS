package dto;

import java.security.SignedObject;
import java.security.cert.Certificate;

public record SignedObjectDTO(SignedObject signedObject, Certificate certificate) {
}
