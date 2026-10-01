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
import org.springframework.stereotype.Service;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Service
public class OcspService {

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
        final OCSPReq request;
        try {
            request = new OCSPReq(requestBytes);
        } catch (Exception malformed) {
            return statusOnly(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        try {
            Req[] requests = request.getRequestList();
            if (requests.length == 0) {
                return statusOnly(OCSPRespBuilder.MALFORMED_REQUEST);
            }

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

                if (!requestedId.matchesIssuer(issuerHolder, calculators)) {
                    status = new UnknownStatus();
                } else {
                    var record = repository.findBySerial(
                            requestedId.getSerialNumber());
                    if (record.isEmpty()) {
                        status = new UnknownStatus();
                    } else if ("REVOKED".equals(record.get().status())) {
                        status = new RevokedStatus(
                                Date.from(record.get().revocationTime()),
                                record.get().revocationReason() == null
                                        ? 0
                                        : record.get().revocationReason());
                    } else {
                        // Bouncy Castle represents the RFC 6960 GOOD status
                        // as CertificateStatus.GOOD, whose value is null.
                        status = CertificateStatus.GOOD;
                    }
                }

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

            return new OCSPRespBuilder()
                    .build(OCSPRespBuilder.SUCCESSFUL, basicResponse)
                    .getEncoded();
        } catch (Exception e) {
            return statusOnly(OCSPRespBuilder.INTERNAL_ERROR);
        }
    }

    private static byte[] statusOnly(int status) {
        try {
            return new OCSPRespBuilder()
                    .build(status, null)
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to encode OCSP response", e);
        }
    }
}
