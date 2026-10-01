package id.taufikiqbal.tte.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import id.taufikiqbal.tte.pki.CrlService;
import id.taufikiqbal.tte.pki.PkiMaterialStore;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@RestController
public class PkiPublicController {

    private static final MediaType PKIX_CERT =
            MediaType.parseMediaType("application/pkix-cert");
    private static final MediaType PKIX_CRL =
            MediaType.parseMediaType("application/pkix-crl");

    private final PkiMaterialStore materialStore;
    private final CrlService crlService;

    public PkiPublicController(
            PkiMaterialStore materialStore,
            CrlService crlService) {
        this.materialStore = materialStore;
        this.crlService = crlService;
    }

    @GetMapping(value = "/pki/root-ca.cer", produces = "application/pkix-cert")
    public ResponseEntity<byte[]> root() throws Exception {
        return certificate(Kind.ROOT);
    }

    @GetMapping(value = "/pki/issuing-ca.cer", produces = "application/pkix-cert")
    public ResponseEntity<byte[]> issuing() throws Exception {
        return certificate(Kind.ISSUING);
    }

    @GetMapping(value = "/pki/ocsp-responder.cer", produces = "application/pkix-cert")
    public ResponseEntity<byte[]> ocsp() throws Exception {
        return certificate(Kind.OCSP);
    }

    @GetMapping(value = "/pki/tsa.cer", produces = "application/pkix-cert")
    public ResponseEntity<byte[]> tsa() throws Exception {
        return certificate(Kind.TSA);
    }

    @GetMapping(
            value = "/pki/crl/root-ca.crl",
            produces = "application/pkix-crl")
    public ResponseEntity<byte[]> rootCrl() {
        return ResponseEntity.ok()
                .contentType(PKIX_CRL)
                .body(crlService.currentRootCaCrl());
    }

    @GetMapping(
            value = "/pki/crl/issuing-ca.crl",
            produces = "application/pkix-crl")
    public ResponseEntity<byte[]> issuingCrl() {
        return ResponseEntity.ok()
                .contentType(PKIX_CRL)
                .body(crlService.currentIssuingCaCrl());
    }

    private ResponseEntity<byte[]> certificate(Kind kind) throws Exception {
        return ResponseEntity.ok()
                .contentType(PKIX_CERT)
                .body(materialStore.load(kind).certificate().getEncoded());
    }
}
