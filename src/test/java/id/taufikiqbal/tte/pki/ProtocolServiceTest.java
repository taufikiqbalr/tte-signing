package id.taufikiqbal.tte.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

class ProtocolServiceTest {

    @BeforeAll
    static void installBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void ocspAndTimestampResponsesAreCryptographicallyValid(
            @TempDir Path tempDir) throws Exception {

        PkiProperties properties = properties(tempDir);
        PkiMaterialStore store = new PkiMaterialStore(properties);
        CertificateRepository repository = mock(CertificateRepository.class);
        CertificateAuthorityService ca =
                new CertificateAuthorityService(properties, store, repository);

        KeyPair rootKeys = ca.generateKeyPair();
        X509Certificate root = ca.createRootCertificate(rootKeys);
        store.write(Kind.ROOT, rootKeys.getPrivate(),
                new X509Certificate[] {root});

        KeyMaterial rootMaterial = store.load(Kind.ROOT);
        KeyPair issuerKeys = ca.generateKeyPair();
        X509Certificate issuer =
                ca.createIssuingCaCertificate(issuerKeys, rootMaterial);
        store.write(Kind.ISSUING, issuerKeys.getPrivate(),
                new X509Certificate[] {issuer, root});

        KeyMaterial issuerMaterial = store.load(Kind.ISSUING);

        KeyPair ocspKeys = ca.generateKeyPair();
        X509Certificate ocspCert =
                ca.createOcspResponderCertificate(ocspKeys, issuerMaterial);
        store.write(Kind.OCSP, ocspKeys.getPrivate(),
                new X509Certificate[] {ocspCert, issuer, root});

        KeyPair tsaKeys = ca.generateKeyPair();
        X509Certificate tsaCert =
                ca.createTsaCertificate(tsaKeys, issuerMaterial);
        store.write(Kind.TSA, tsaKeys.getPrivate(),
                new X509Certificate[] {tsaCert, issuer, root});

        CertificateAuthorityService.IssuedCertificate issued =
                ca.issueDocumentSigner(
                        new CertificateAuthorityService.SubjectData(
                                "Protocol Test Signer",
                                "Example",
                                "PKI",
                                "ID",
                                "protocol@example.test"),
                        30,
                        "protocol-test-p12-password".toCharArray());

        X509Certificate signer = issued.certificate();
        CertificateRepository.CertificateRecord active =
                new CertificateRepository.CertificateRecord(
                        signer.getSerialNumber().toString(16).toUpperCase(),
                        signer.getSubjectX500Principal().getName(),
                        signer.getEncoded(),
                        signer.getNotBefore().toInstant(),
                        signer.getNotAfter().toInstant(),
                        "GOOD",
                        null,
                        null);
        when(repository.findBySerial(any(BigInteger.class)))
                .thenReturn(Optional.of(active));

        verifyOcsp(repository, store, properties, issuer, ocspCert, signer);
        verifyTsa(repository, store, properties, tsaCert);
    }

    private static void verifyOcsp(
            CertificateRepository repository,
            PkiMaterialStore store,
            PkiProperties properties,
            X509Certificate issuer,
            X509Certificate ocspCert,
            X509Certificate signer) throws Exception {

        DigestCalculatorProvider calculators =
                new JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC")
                        .build();
        CertificateID certId = new CertificateID(
                calculators.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer),
                signer.getSerialNumber());

        OCSPReqBuilder requestBuilder = new OCSPReqBuilder();
        requestBuilder.addRequest(certId);

        byte[] nonce = new byte[] {1, 3, 3, 7, 9, 9};
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false,
                new DEROctetString(nonce));
        requestBuilder.setRequestExtensions(extensions.generate());

        OCSPReq request = requestBuilder.build();
        OcspService service = new OcspService(
                properties, store, repository);
        OCSPResp response = new OCSPResp(
                service.respond(request.getEncoded()));

        assertEquals(OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
        assertNotNull(basic);
        assertEquals(1, basic.getResponses().length);

        SingleResp single = basic.getResponses()[0];
        assertNull(single.getCertStatus());
        assertEquals(signer.getSerialNumber(),
                single.getCertID().getSerialNumber());

        Extension requestNonce = request.getExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        Extension responseNonce = basic.getExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        assertNotNull(responseNonce);
        assertArrayEquals(
                requestNonce.getExtnValue().getOctets(),
                responseNonce.getExtnValue().getOctets());

        assertTrue(basic.isSignatureValid(
                new JcaContentVerifierProviderBuilder()
                        .setProvider("BC")
                        .build(ocspCert)));
    }

    private static void verifyTsa(
            CertificateRepository repository,
            PkiMaterialStore store,
            PkiProperties properties,
            X509Certificate tsaCert) throws Exception {

        BigInteger serial = BigInteger.valueOf(7);
        when(repository.nextTsaSerial()).thenReturn(serial);

        byte[] imprint = MessageDigest.getInstance("SHA-256")
                .digest("timestamp-me".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        TimeStampRequestGenerator generator =
                new TimeStampRequestGenerator();
        generator.setCertReq(true);
        generator.setReqPolicy(
                new ASN1ObjectIdentifier(properties.getTsaPolicyOid()));

        TimeStampRequest request = generator.generate(
                TSPAlgorithms.SHA256,
                imprint,
                BigInteger.valueOf(424242));

        TsaService service = new TsaService(
                properties, store, repository);
        TimeStampResponse response = new TimeStampResponse(
                service.timestamp(request.getEncoded()));

        response.validate(request);
        TimeStampToken token = response.getTimeStampToken();
        assertNotNull(token);
        assertEquals(serial,
                token.getTimeStampInfo().getSerialNumber());

        token.validate(
                new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC")
                        .build(tsaCert));
    }

    private static PkiProperties properties(Path tempDir) {
        PkiProperties properties = new PkiProperties();
        properties.setBaseDir(tempDir);
        properties.setStorePassword("protocol-store-password-12345");
        properties.setPublicBaseUrl("https://pki.example.test");
        properties.setRootSubject("CN=Protocol Root CA,O=Example,C=ID");
        properties.setIssuingSubject("CN=Protocol Issuing CA,O=Example,C=ID");
        properties.setOcspSubject("CN=Protocol OCSP,O=Example,C=ID");
        properties.setTsaSubject("CN=Protocol TSA,O=Example,C=ID");
        properties.setTsaPolicyOid("1.3.6.1.4.1.55555.1.1");
        return properties;
    }
}
