package id.taufikiqbal.tte.web;

import java.security.cert.X509Certificate;

import jakarta.validation.Valid;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import id.taufikiqbal.tte.pki.CertificateAuthorityService;
import id.taufikiqbal.tte.pki.CertificateRepository;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {

    private static final MediaType PKCS12 =
            MediaType.parseMediaType("application/x-pkcs12");

    private final CertificateAuthorityService certificateAuthorityService;
    private final CertificateRepository repository;

    public CertificateController(
            CertificateAuthorityService certificateAuthorityService,
            CertificateRepository repository) {
        this.certificateAuthorityService = certificateAuthorityService;
        this.repository = repository;
    }

    @PostMapping(
            value = "/issue",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = "application/x-pkcs12")
    public ResponseEntity<byte[]> issue(
            @Valid @RequestBody ApiModels.IssueCertificateRequest request) {

        CertificateAuthorityService.SubjectData subject =
                new CertificateAuthorityService.SubjectData(
                        request.commonName(),
                        request.organization(),
                        request.organizationalUnit(),
                        request.country(),
                        request.email());

        CertificateAuthorityService.IssuedCertificate issued =
                certificateAuthorityService.issueDocumentSigner(
                        subject,
                        request.validityDays(),
                        request.pkcs12Password().toCharArray());

        String serial = issued.certificate()
                .getSerialNumber().toString(16).toUpperCase();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(PKCS12);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("signer-" + serial + ".p12")
                .build());
        headers.add("X-Certificate-Serial", serial);

        return ResponseEntity.ok()
                .headers(headers)
                .body(issued.pkcs12());
    }

    @GetMapping("/{serial}")
    public ApiModels.CertificateMetadata get(
            @PathVariable String serial) {

        CertificateRepository.CertificateRecord record =
                repository.findBySerialHex(serial)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Certificate serial not found"));
        X509Certificate certificate = record.certificate();

        return new ApiModels.CertificateMetadata(
                record.serialHex(),
                record.subjectDn(),
                certificate.getIssuerX500Principal().getName(),
                record.notBefore().toString(),
                record.notAfter().toString(),
                record.status(),
                record.revocationTime() == null
                        ? null : record.revocationTime().toString(),
                record.revocationReason());
    }

    @PostMapping("/{serial}/revoke")
    public ResponseEntity<Void> revoke(
            @PathVariable String serial,
            @Valid @RequestBody ApiModels.RevokeCertificateRequest request) {

        repository.revoke(
                serial,
                ApiModels.revocationReasonCode(request.reason()));
        return ResponseEntity.noContent().build();
    }
}
