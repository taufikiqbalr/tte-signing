package id.taufikiqbal.tte.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import id.taufikiqbal.tte.pki.OcspService;

@RestController
public class OcspController {

    private static final MediaType OCSP_RESPONSE =
            MediaType.parseMediaType("application/ocsp-response");

    private final OcspService ocspService;

    public OcspController(OcspService ocspService) {
        this.ocspService = ocspService;
    }

    @PostMapping(
            value = "/ocsp",
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocsp(@RequestBody byte[] request) {
        return ResponseEntity.ok()
                .contentType(OCSP_RESPONSE)
                .body(ocspService.respond(request));
    }
}
