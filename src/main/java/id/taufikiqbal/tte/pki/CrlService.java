package id.taufikiqbal.tte.pki;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Service
public class CrlService {

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateRepository repository;

    public CrlService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateRepository repository) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.repository = repository;
    }

    public byte[] currentIssuingCaCrl() {
        try {
            KeyMaterial issuer = materialStore.load(Kind.ISSUING);
            Instant now = Instant.now();

            X509v2CRLBuilder builder = new X509v2CRLBuilder(
                    new JcaX509CertificateHolder(issuer.certificate()).getSubject(),
                    Date.from(now));
            builder.setNextUpdate(
                    Date.from(now.plus(
                            properties.getCrlValidityHours(), ChronoUnit.HOURS)));

            for (CertificateRepository.CertificateRecord revoked
                    : repository.findRevoked()) {
                builder.addCRLEntry(
                        revoked.serialNumber(),
                        Date.from(revoked.revocationTime()),
                        revoked.revocationReason() == null
                                ? 0 : revoked.revocationReason());
            }

            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            builder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extensions.createAuthorityKeyIdentifier(issuer.certificate()));
            builder.addExtension(
                    Extension.cRLNumber,
                    false,
                    new CRLNumber(BigInteger.valueOf(now.getEpochSecond())));

            ContentSigner signer = new JcaContentSignerBuilder("SHA384withRSA")
                    .setProvider("BC")
                    .build(issuer.privateKey());
            X509CRLHolder crl = builder.build(signer);
            return crl.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate CRL", e);
        }
    }
}
