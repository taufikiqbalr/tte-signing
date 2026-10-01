package id.taufikiqbal.tte.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import id.taufikiqbal.tte.pki.TsaService;

@RestController
public class TsaController {

    private static final MediaType TIMESTAMP_REPLY =
            MediaType.parseMediaType("application/timestamp-reply");

    private final TsaService tsaService;

    public TsaController(TsaService tsaService) {
        this.tsaService = tsaService;
    }

    @PostMapping(
            value = "/tsa",
            consumes = "application/timestamp-query",
            produces = "application/timestamp-reply")
    public ResponseEntity<byte[]> timestamp(@RequestBody byte[] request) {
        return ResponseEntity.ok()
                .contentType(TIMESTAMP_REPLY)
                .body(tsaService.timestamp(request));
    }
}
