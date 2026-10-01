package id.taufikiqbal.tte.web;

import java.io.IOException;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import id.taufikiqbal.tte.signing.PadesSigningService;

@RestController
@RequestMapping("/api/v1/signatures/pdf")
public class SigningController {

    private final PadesSigningService signingService;

    public SigningController(PadesSigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping(
            value = "/sign",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> sign(
            @RequestPart("document") MultipartFile document,
            @RequestPart("pkcs12") MultipartFile pkcs12,
            @RequestParam("password") String password,
            @RequestParam(value = "level", defaultValue = "T") String level)
            throws IOException {

        requireNonEmpty(document, "document");
        requireNonEmpty(pkcs12, "pkcs12");

        byte[] output = signingService.sign(
                document.getBytes(),
                pkcs12.getBytes(),
                password.toCharArray(),
                level);

        return pdfResponse(
                output,
                "signed-" + safeName(document.getOriginalFilename()));
    }

    @PostMapping(
            value = "/extend",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> extend(
            @RequestPart("document") MultipartFile document,
            @RequestParam("level") String level)
            throws IOException {

        requireNonEmpty(document, "document");

        byte[] output = signingService.extend(
                document.getBytes(), level);

        return pdfResponse(
                output,
                "extended-" + safeName(document.getOriginalFilename()));
    }

    @PostMapping(
            value = "/validate",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> validate(
            @RequestPart("document") MultipartFile document)
            throws IOException {

        requireNonEmpty(document, "document");
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .body(signingService.validate(document.getBytes()));
    }

    private static ResponseEntity<byte[]> pdfResponse(
            byte[] body,
            String filename) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(filename)
                .build());
        return ResponseEntity.ok()
                .headers(headers)
                .body(body);
    }

    private static void requireNonEmpty(
            MultipartFile file,
            String fieldName) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException(
                    fieldName + " must not be empty");
        }
    }

    private static String safeName(String value) {
        if (value == null || value.isBlank()) {
            return "document.pdf";
        }
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
