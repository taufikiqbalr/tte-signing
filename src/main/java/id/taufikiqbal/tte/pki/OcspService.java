package id.taufikiqbal.tte.pki;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Service
public class OcspService {

    private static final Logger log =
            LoggerFactory.getLogger(OcspService.class);

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateRepository repository;

    public OcspService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateRepository repository) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.repository = repository;
    }

    public byte[] respond(byte[] requestBytes) {
        log.info(
                "OCSP request received bytes={}",
                requestBytes == null ? 0 : requestBytes.length);

        final OCSPReq request;
        try {
            request = new OCSPReq(requestBytes);
        } catch (Exception malformed) {
            log.warn(
                    "OCSP malformed request bytes={} exceptionType={} message={}",
                    requestBytes == null ? 0 : requestBytes.length,
                    malformed.getClass().getName(),
                    malformed.getMessage(),
                    malformed);
            return statusOnly(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        try {
            Req[] requests = request.getRequestList();
            if (requests.length == 0) {
                log.warn("OCSP request contains no SingleRequest entries");
                return statusOnly(OCSPRespBuilder.MALFORMED_REQUEST);
            }
            log.info("OCSP processing requestCount={}", requests.length);

            KeyMaterial issuer = materialStore.load(Kind.ISSUING);
            KeyMaterial responder = materialStore.load(Kind.OCSP);
            DigestCalculatorProvider calculators =
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider("BC")
                            .build();

            JcaBasicOCSPRespBuilder responseBuilder =
                    new JcaBasicOCSPRespBuilder(
                            responder.certificate().getPublicKey(),
                            calculators.get(CertificateID.HASH_SHA1));

            Instant now = Instant.now();
            Date thisUpdate = Date.from(now);
            Date nextUpdate = Date.from(
                    now.plus(properties.getOcspValidityMinutes(),
                            ChronoUnit.MINUTES));
            X509CertificateHolder issuerHolder =
                    new JcaX509CertificateHolder(issuer.certificate());

            for (Req singleRequest : requests) {
                CertificateID requestedId = singleRequest.getCertID();
                CertificateStatus status;
                String statusLabel;

                if (!requestedId.matchesIssuer(issuerHolder, calculators)) {
                    status = new UnknownStatus();
                    statusLabel = "UNKNOWN_ISSUER";
                } else {
                    var record = repository.findBySerial(
                            requestedId.getSerialNumber());
                    if (record.isEmpty()) {
                        status = new UnknownStatus();
                        statusLabel = "UNKNOWN_SERIAL";
                    } else if ("REVOKED".equals(record.get().status())) {
                        status = new RevokedStatus(
                                Date.from(record.get().revocationTime()),
                                record.get().revocationReason() == null
                                        ? 0
                                        : record.get().revocationReason());
                        statusLabel = "REVOKED";
                    } else {
                        // Bouncy Castle represents the RFC 6960 GOOD status
                        // as CertificateStatus.GOOD, whose value is null.
                        status = CertificateStatus.GOOD;
                        statusLabel = "GOOD";
                    }
                }

                log.info(
                        "OCSP certificate status serial={} status={}",
                        requestedId.getSerialNumber().toString(16).toUpperCase(),
                        statusLabel);

                responseBuilder.addResponse(
                        requestedId,
                        status,
                        thisUpdate,
                        nextUpdate,
                        null);
            }

            Extension nonce = request.getExtension(
                    org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonce != null) {
                responseBuilder.setResponseExtensions(
                        new Extensions(new Extension[] {nonce}));
            }

            ContentSigner responseSigner =
                    new JcaContentSignerBuilder("SHA384withRSA")
                            .setProvider("BC")
                            .build(responder.privateKey());

            BasicOCSPResp basicResponse = responseBuilder.build(
                    responseSigner,
                    new X509CertificateHolder[] {
                            new JcaX509CertificateHolder(
                                    responder.certificate())
                    },
                    Date.from(now));

            byte[] encoded = new OCSPRespBuilder()
                    .build(OCSPRespBuilder.SUCCESSFUL, basicResponse)
                    .getEncoded();
            log.info(
                    "OCSP response generated requestCount={} bytes={}",
                    requests.length, encoded.length);
            return encoded;
        } catch (Exception e) {
            log.error(
                    "OCSP responder failure bytes={} exceptionType={} message={}",
                    requestBytes == null ? 0 : requestBytes.length,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            return statusOnly(OCSPRespBuilder.INTERNAL_ERROR);
        }
    }

    private static byte[] statusOnly(int status) {
        try {
            return new OCSPRespBuilder()
                    .build(status, null)
                    .getEncoded();
        } catch (Exception e) {
            log.error(
                    "Unable to encode OCSP status-only response status={} exceptionType={} message={}",
                    status,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalStateException(
                    "Unable to encode OCSP response", e);
        }
    }
}
