package id.taufikiqbal.tte.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class ApiModels {

    private ApiModels() {
    }

    public record IssueCertificateRequest(
            @NotBlank @Size(max = 200) String commonName,
            @Size(max = 200) String organization,
            @Size(max = 200) String organizationalUnit,
            @Pattern(regexp = "^[A-Za-z]{2}$") String country,
            @Email @Size(max = 320) String email,
            @Min(1) @Max(3650) Integer validityDays,
            @NotBlank @Size(min = 12, max = 256) String pkcs12Password) {
    }

    public record RevokeCertificateRequest(
            @NotBlank String reason) {
    }

    public record CertificateMetadata(
            String serialHex,
            String subjectDn,
            String issuerDn,
            String notBefore,
            String notAfter,
            String status,
            String revocationTime,
            Integer revocationReason) {
    }

    public static int revocationReasonCode(String reason) {
        return switch (reason.toLowerCase()) {
            case "unspecified" -> 0;
            case "keycompromise", "key_compromise" -> 1;
            case "affiliationchanged", "affiliation_changed" -> 3;
            case "superseded" -> 4;
            case "cessationofoperation", "cessation_of_operation" -> 5;
            case "certificatehold", "certificate_hold" -> 6;
            case "privilegewithdrawn", "privilege_withdrawn" -> 9;
            default -> throw new IllegalArgumentException(
                    "Unsupported revocation reason");
        };
    }
}
