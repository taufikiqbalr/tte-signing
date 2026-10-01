package id.taufikiqbal.tte.signing;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore.PasswordProtection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Service
public class PadesSigningService {

    private static final Logger log =
            LoggerFactory.getLogger(PadesSigningService.class);

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;

    public PadesSigningService(
            PkiProperties properties,
            PkiMaterialStore materialStore) {
        this.properties = properties;
        this.materialStore = materialStore;
    }

    public byte[] sign(
            byte[] pdf,
            byte[] pkcs12,
            char[] password,
            String requestedLevel) {

        SignatureLevel level = switch (
                requestedLevel == null ? "T" : requestedLevel.toUpperCase()) {
            case "B" -> SignatureLevel.PAdES_BASELINE_B;
            case "T" -> SignatureLevel.PAdES_BASELINE_T;
            default -> throw new IllegalArgumentException(
                    "Initial signing level must be B or T");
        };

        log.info(
                "PAdES signing started level={} pdfBytes={} pkcs12Bytes={}",
                level, pdf == null ? 0 : pdf.length,
                pkcs12 == null ? 0 : pkcs12.length);

        Pkcs12InputValidator.validate(pkcs12, password);

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                pkcs12, new PasswordProtection(password))) {

            DSSPrivateKeyEntry key = token.getKeys().stream()
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PKCS#12 contains no signing key"));

            log.info(
                    "PKCS#12 loaded successfully certificateChainSize={}",
                    key.getCertificateChain().length);

            PAdESSignatureParameters parameters =
                    new PAdESSignatureParameters();
            parameters.setSignatureLevel(level);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
            parameters.setSigningCertificate(key.getCertificate());
            parameters.setCertificateChain(key.getCertificateChain());

            PAdESService service = createPadesService();
            DSSDocument input = pdfDocument(pdf);

            ToBeSigned dataToSign =
                    service.getDataToSign(input, parameters);
            SignatureValue signatureValue = token.sign(
                    dataToSign,
                    parameters.getDigestAlgorithm(),
                    key);

            DSSDocument signed =
                    service.signDocument(input, parameters, signatureValue);
            byte[] output = toBytes(signed);
            log.info(
                    "PAdES signing completed level={} outputBytes={}",
                    level, output.length);
            return output;
        } catch (IllegalArgumentException e) {
            log.warn(
                    "PAdES signing rejected level={} reason={}",
                    level, e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error(
                    "PAdES signing failed level={} pdfBytes={} pkcs12Bytes={} exceptionType={} message={}",
                    level,
                    pdf == null ? 0 : pdf.length,
                    pkcs12 == null ? 0 : pkcs12.length,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalStateException("Unable to sign PDF", e);
        }
    }

    public byte[] extend(byte[] signedPdf, String requestedLevel) {
        SignatureLevel level = switch (
                requestedLevel == null ? "" : requestedLevel.toUpperCase()) {
            case "LT" -> SignatureLevel.PAdES_BASELINE_LT;
            case "LTA" -> SignatureLevel.PAdES_BASELINE_LTA;
            default -> throw new IllegalArgumentException(
                    "Extension level must be LT or LTA");
        };

        log.info(
                "PAdES LTV extension started targetLevel={} pdfBytes={}",
                level, signedPdf == null ? 0 : signedPdf.length);

        try {
            PAdESSignatureParameters parameters =
                    new PAdESSignatureParameters();
            parameters.setSignatureLevel(level);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA384);

            DSSDocument extended = createPadesService()
                    .extendDocument(pdfDocument(signedPdf), parameters);
            byte[] output = toBytes(extended);
            log.info(
                    "PAdES LTV extension completed targetLevel={} outputBytes={}",
                    level, output.length);
            return output;
        } catch (Exception e) {
            log.error(
                    "PAdES LTV extension failed targetLevel={} pdfBytes={} exceptionType={} message={}",
                    level,
                    signedPdf == null ? 0 : signedPdf.length,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalStateException(
                    "Unable to extend PDF signature to " + requestedLevel, e);
        }
    }

    public String validate(byte[] signedPdf) {
        log.info(
                "PAdES validation started pdfBytes={}",
                signedPdf == null ? 0 : signedPdf.length);
        try {
            SignedDocumentValidator validator =
                    SignedDocumentValidator.fromDocument(
                            pdfDocument(signedPdf));
            validator.setCertificateVerifier(createCertificateVerifier());
            Reports reports = validator.validateDocument();
            String report = reports.getXmlSimpleReport();
            log.info(
                    "PAdES validation completed reportChars={}",
                    report == null ? 0 : report.length());
            return report;
        } catch (Exception e) {
            log.error(
                    "PAdES validation failed pdfBytes={} exceptionType={} message={}",
                    signedPdf == null ? 0 : signedPdf.length,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalStateException(
                    "Unable to validate signed PDF", e);
        }
    }

    private PAdESService createPadesService() {
        PAdESService service =
                new PAdESService(createCertificateVerifier());
        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());

        String tsaUrl = properties.getPublicBaseUrl() + "/tsa";
        log.debug("Configuring DSS TSA source url={}", tsaUrl);
        OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl);
        tspSource.setPolicyOid(properties.getTsaPolicyOid());
        tspSource.setNonceSource(new SecureRandomNonceSource());
        service.setTspSource(tspSource);
        return service;
    }

    private CommonCertificateVerifier createCertificateVerifier() {
        CommonTrustedCertificateSource trusted =
                new CommonTrustedCertificateSource();
        trusted.addCertificate(new CertificateToken(
                materialStore.load(Kind.ROOT).certificate()));

        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setNonceSource(new SecureRandomNonceSource());

        CommonCertificateVerifier verifier =
                new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setOcspSource(ocspSource);
        verifier.setCrlSource(new OnlineCRLSource());
        return verifier;
    }

    private static DSSDocument pdfDocument(byte[] bytes) {
        return new InMemoryDocument(
                bytes, "document.pdf", MimeTypeEnum.PDF);
    }

    private static byte[] toBytes(DSSDocument document) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        document.writeTo(out);
        return out.toByteArray();
    }
}
