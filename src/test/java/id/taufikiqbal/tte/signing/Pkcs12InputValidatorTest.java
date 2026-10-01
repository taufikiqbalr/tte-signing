package id.taufikiqbal.tte.signing;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class Pkcs12InputValidatorTest {

    @Test
    void rejectsJsonSavedAsP12() {
        byte[] fakeP12 = """
                {"status":500,"error":"Internal Server Error","message":"The operation could not be completed"}
                """.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs12InputValidator.validate(
                        fakeP12, "some-password".toCharArray()));

        assertTrue(error.getMessage().contains("JSON/text"));
    }

    @Test
    void acceptsValidPkcs12WithPrivateKey() throws Exception {
        char[] password = "valid-test-password".toCharArray();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keyPair = generator.generateKeyPair();

        var subject = new X500Name("CN=PKCS12 Test");
        var now = new java.util.Date();
        var later = new java.util.Date(now.getTime() + 86_400_000L);
        var builder = new JcaX509v3CertificateBuilder(
                subject,
                java.math.BigInteger.ONE,
                now,
                later,
                subject,
                keyPair.getPublic());

        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
        X509Certificate certificate =
                new JcaX509CertificateConverter().getCertificate(
                        builder.build(signer));

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, password);
        store.setKeyEntry(
                "signer",
                keyPair.getPrivate(),
                password,
                new X509Certificate[] {certificate});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, password);

        assertDoesNotThrow(() ->
                Pkcs12InputValidator.validate(
                        out.toByteArray(), password));
    }
}
