package id.taufikiqbal.tte.pki;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;

@Service
public class CertificateAuthorityService {

    private static final Logger log =
            LoggerFactory.getLogger(CertificateAuthorityService.class);

    public static final String DOCUMENT_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.36";

    public record SubjectData(
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String email) {
    }

    public record IssuedCertificate(
            X509Certificate certificate,
            byte[] pkcs12) {
    }

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateRepository certificateRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public CertificateAuthorityService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateRepository certificateRepository) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.certificateRepository = certificateRepository;
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072, secureRandom);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate RSA key pair", e);
        }
    }

    public X509Certificate createRootCertificate(KeyPair keyPair) {
        try {
            X500Name subject = new X500Name(properties.getRootSubject());
            Instant now = Instant.now().minus(5, ChronoUnit.MINUTES);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    randomSerial(),
                    Date.from(now),
                    Date.from(now.plus(properties.getRootValidityDays(), ChronoUnit.DAYS)),
                    subject,
                    keyPair.getPublic());

            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensions.createAuthorityKeyIdentifier(keyPair.getPublic()));

            return signAndConvert(builder, keyPair.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create Root CA certificate", e);
        }
    }

    public X509Certificate createIssuingCaCertificate(
            KeyPair keyPair,
            KeyMaterial root) {
        try {
            X500Name subject = new X500Name(properties.getIssuingSubject());
            X500Name issuer = new JcaX509CertificateHolder(root.certificate()).getSubject();
            Instant now = Instant.now().minus(5, ChronoUnit.MINUTES);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer,
                    randomSerial(),
                    Date.from(now),
                    Date.from(now.plus(properties.getIssuerValidityDays(), ChronoUnit.DAYS)),
                    subject,
                    keyPair.getPublic());

            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensions.createAuthorityKeyIdentifier(root.certificate()));

            addCaIssuersAia(builder, properties.getPublicBaseUrl() + "/pki/root-ca.cer");

            X509Certificate certificate = signAndConvert(builder, root.privateKey());
            certificate.verify(root.certificate().getPublicKey());
            return certificate;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create Issuing CA certificate", e);
        }
    }

    public X509Certificate createOcspResponderCertificate(
            KeyPair keyPair,
            KeyMaterial issuer) {
        try {
            X509v3CertificateBuilder builder = serviceCertificateBuilder(
                    properties.getOcspSubject(), keyPair, issuer);

            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
            builder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck,
                    false, DERNull.INSTANCE);

            X509Certificate certificate = signAndConvert(builder, issuer.privateKey());
            certificate.verify(issuer.certificate().getPublicKey());
            return certificate;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create OCSP responder certificate", e);
        }
    }

    public X509Certificate createTsaCertificate(
            KeyPair keyPair,
            KeyMaterial issuer) {
        try {
            X509v3CertificateBuilder builder = serviceCertificateBuilder(
                    properties.getTsaSubject(), keyPair, issuer);

            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

            // RFC 3161: the TSA certificate MUST contain only id-kp-timeStamping,
            // and the EKU extension MUST be critical.
            builder.addExtension(Extension.extendedKeyUsage, true,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

            X509Certificate certificate = signAndConvert(builder, issuer.privateKey());
            certificate.verify(issuer.certificate().getPublicKey());
            return certificate;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create TSA certificate", e);
        }
    }

    public IssuedCertificate issueDocumentSigner(
            SubjectData subjectData,
            Integer requestedValidityDays,
            char[] pkcs12Password) {

        int validityDays = requestedValidityDays == null
                ? properties.getEndEntityValidityDays()
                : requestedValidityDays;

        if (validityDays < 1 || validityDays > properties.getMaxEndEntityValidityDays()) {
            throw new IllegalArgumentException(
                    "validityDays must be between 1 and "
                            + properties.getMaxEndEntityValidityDays());
        }
        if (pkcs12Password == null || pkcs12Password.length < 12) {
            throw new IllegalArgumentException(
                    "PKCS#12 password must be at least 12 characters");
        }

        log.info(
                "Document signer certificate issuance started validityDays={}",
                validityDays);

        try {
            KeyMaterial issuer = materialStore.load(PkiMaterialStore.Kind.ISSUING);
            KeyPair keyPair = generateKeyPair();
            X500Name subject = buildSubject(subjectData);
            Instant now = Instant.now().minus(5, ChronoUnit.MINUTES);
            Instant requestedNotAfter =
                    now.plus(validityDays, ChronoUnit.DAYS);
            Instant issuerNotAfter =
                    issuer.certificate().getNotAfter().toInstant();
            if (requestedNotAfter.isAfter(issuerNotAfter)) {
                throw new IllegalArgumentException(
                        "Requested certificate validity exceeds Issuing CA validity");
            }

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new JcaX509CertificateHolder(issuer.certificate()).getSubject(),
                    randomSerial(),
                    Date.from(now),
                    Date.from(requestedNotAfter),
                    subject,
                    keyPair.getPublic());

            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.getInstance(
                            new ASN1ObjectIdentifier(DOCUMENT_SIGNING_EKU_OID))));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensions.createAuthorityKeyIdentifier(issuer.certificate()));
            addAuthorityAndRevocationPointers(builder);

            if (subjectData.email() != null && !subjectData.email().isBlank()) {
                builder.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(
                                GeneralName.rfc822Name, subjectData.email())));
            }

            X509Certificate certificate = signAndConvert(builder, issuer.privateKey());
            certificate.verify(issuer.certificate().getPublicKey());
            certificateRepository.save(certificate);

            byte[] pkcs12 = buildPkcs12(
                    keyPair,
                    new X509Certificate[] {
                            certificate,
                            issuer.certificate(),
                            materialStore.load(PkiMaterialStore.Kind.ROOT).certificate()
                    },
                    pkcs12Password);

            log.info(
                    "Document signer certificate issued serial={} notAfter={} pkcs12Bytes={} chainSize={}",
                    certificate.getSerialNumber().toString(16).toUpperCase(),
                    certificate.getNotAfter().toInstant(),
                    pkcs12.length,
                    3);
            return new IssuedCertificate(certificate, pkcs12);
        } catch (IllegalArgumentException e) {
            log.warn(
                    "Document signer certificate issuance rejected reason={}",
                    e.getMessage(),
                    e);
            throw e;
        } catch (Exception e) {
            log.error(
                    "Document signer certificate issuance failed validityDays={} exceptionType={} message={}",
                    validityDays,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalStateException("Unable to issue document signing certificate", e);
        }
    }

    private X509v3CertificateBuilder serviceCertificateBuilder(
            String subjectDn,
            KeyPair keyPair,
            KeyMaterial issuer) throws Exception {

        Instant now = Instant.now().minus(5, ChronoUnit.MINUTES);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new JcaX509CertificateHolder(issuer.certificate()).getSubject(),
                randomSerial(),
                Date.from(now),
                Date.from(now.plus(properties.getServiceValidityDays(), ChronoUnit.DAYS)),
                new X500Name(subjectDn),
                keyPair.getPublic());

        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(issuer.certificate()));
        addAuthorityAndRevocationPointers(builder);
        return builder;
    }

    private void addAuthorityAndRevocationPointers(
            X509v3CertificateBuilder builder) throws Exception {

        AccessDescription ocsp = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        properties.getPublicBaseUrl() + "/ocsp"));
        AccessDescription caIssuers = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        properties.getPublicBaseUrl() + "/pki/issuing-ca.cer"));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(new AccessDescription[] {ocsp, caIssuers}));

        GeneralName crlUrl = new GeneralName(
                GeneralName.uniformResourceIdentifier,
                properties.getPublicBaseUrl() + "/pki/crl/issuing-ca.crl");
        DistributionPointName distributionPointName = new DistributionPointName(
                new GeneralNames(crlUrl));
        DistributionPoint distributionPoint = new DistributionPoint(
                distributionPointName, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(
                        new DistributionPoint[] {distributionPoint}));
    }

    private void addCaIssuersAia(
            X509v3CertificateBuilder builder,
            String url) throws Exception {

        AccessDescription caIssuers = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, url));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(caIssuers));
    }

    private X500Name buildSubject(SubjectData data) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, data.commonName());
        if (data.organizationalUnit() != null && !data.organizationalUnit().isBlank()) {
            builder.addRDN(BCStyle.OU, data.organizationalUnit());
        }
        if (data.organization() != null && !data.organization().isBlank()) {
            builder.addRDN(BCStyle.O, data.organization());
        }
        if (data.country() != null && !data.country().isBlank()) {
            builder.addRDN(BCStyle.C, data.country().toUpperCase());
        }
        return builder.build();
    }

    private X509Certificate signAndConvert(
            X509v3CertificateBuilder builder,
            java.security.PrivateKey signingKey) throws Exception {

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withRSA")
                .setProvider("BC")
                .build(signingKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    private byte[] buildPkcs12(
            KeyPair keyPair,
            X509Certificate[] chain,
            char[] password) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password);
        keyStore.setKeyEntry("signing-key", keyPair.getPrivate(), password, chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);
        byte[] encoded = out.toByteArray();
        log.debug(
                "PKCS12 signer bundle created alias=signing-key chainSize={} bytes={}",
                chain == null ? 0 : chain.length,
                encoded.length);
        return encoded;
    }

    private BigInteger randomSerial() {
        BigInteger serial;
        do {
            serial = new BigInteger(159, secureRandom);
        } while (serial.signum() <= 0);
        return serial;
    }
}
