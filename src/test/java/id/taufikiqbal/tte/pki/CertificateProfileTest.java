package id.taufikiqbal.tte.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

class CertificateProfileTest {

    @BeforeAll
    static void installBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void profilesContainRequiredConstraintsAndEkus(@TempDir Path tempDir)
            throws Exception {

        PkiProperties properties = new PkiProperties();
        properties.setBaseDir(tempDir);
        properties.setStorePassword("test-store-password-12345");
        properties.setPublicBaseUrl("https://pki.example.test");
        properties.setRootSubject("CN=Test Root CA,O=Example,C=ID");
        properties.setIssuingSubject("CN=Test Issuing CA,O=Example,C=ID");
        properties.setOcspSubject("CN=Test OCSP,O=Example,C=ID");
        properties.setTsaSubject("CN=Test TSA,O=Example,C=ID");
        properties.setTsaPolicyOid("1.3.6.1.4.1.55555.1.1");

        PkiMaterialStore store = new PkiMaterialStore(properties);
        CertificateRepository repository = mock(CertificateRepository.class);
        CertificateAuthorityService ca =
                new CertificateAuthorityService(properties, store, repository);

        KeyPair rootKeys = ca.generateKeyPair();
        X509Certificate root = ca.createRootCertificate(rootKeys);
        store.write(
                Kind.ROOT,
                rootKeys.getPrivate(),
                new X509Certificate[] {root});

        KeyMaterial rootMaterial = store.load(Kind.ROOT);
        KeyPair issuerKeys = ca.generateKeyPair();
        X509Certificate issuer =
                ca.createIssuingCaCertificate(issuerKeys, rootMaterial);
        store.write(
                Kind.ISSUING,
                issuerKeys.getPrivate(),
                new X509Certificate[] {issuer, root});

        KeyMaterial issuerMaterial = store.load(Kind.ISSUING);
        X509Certificate ocsp = ca.createOcspResponderCertificate(
                ca.generateKeyPair(), issuerMaterial);
        X509Certificate tsa = ca.createTsaCertificate(
                ca.generateKeyPair(), issuerMaterial);

        CertificateAuthorityService.IssuedCertificate signer =
                ca.issueDocumentSigner(
                        new CertificateAuthorityService.SubjectData(
                                "Alice Signer",
                                "Example",
                                "Signing",
                                "ID",
                                "alice@example.test"),
                        30,
                        "test-p12-password-12345".toCharArray());

        assertEquals(1, root.getBasicConstraints());
        assertEquals(0, issuer.getBasicConstraints());
        assertEquals(-1, ocsp.getBasicConstraints());
        assertEquals(-1, tsa.getBasicConstraints());
        assertEquals(-1, signer.certificate().getBasicConstraints());

        assertTrue(ocsp.getExtendedKeyUsage()
                .contains("1.3.6.1.5.5.7.3.9"));

        List<String> tsaEku = tsa.getExtendedKeyUsage();
        assertEquals(List.of("1.3.6.1.5.5.7.3.8"), tsaEku);
        assertTrue(tsa.getCriticalExtensionOIDs()
                .contains(Extension.extendedKeyUsage.getId()));

        assertTrue(signer.certificate().getExtendedKeyUsage()
                .contains(CertificateAuthorityService.DOCUMENT_SIGNING_EKU_OID));
        assertNotNull(signer.certificate()
                .getExtensionValue(Extension.authorityInfoAccess.getId()));
        assertNotNull(signer.certificate()
                .getExtensionValue(Extension.cRLDistributionPoints.getId()));

        assertTrue(signer.pkcs12().length > 0);
        signer.certificate().verify(issuer.getPublicKey());
        issuer.verify(root.getPublicKey());
    }
}
