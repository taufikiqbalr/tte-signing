package id.taufikiqbal.tte.pki;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import id.taufikiqbal.tte.config.PkiProperties;

@Component
public class PkiMaterialStore {

    public enum Kind {
        ROOT("root-ca.p12", "root-ca"),
        ISSUING("issuing-ca.p12", "issuing-ca"),
        OCSP("ocsp-responder.p12", "ocsp-responder"),
        TSA("tsa.p12", "tsa");

        private final String fileName;
        private final String alias;

        Kind(String fileName, String alias) {
            this.fileName = fileName;
            this.alias = alias;
        }

        public String fileName() { return fileName; }
        public String alias() { return alias; }
    }

    public record KeyMaterial(
            PrivateKey privateKey,
            X509Certificate certificate,
            List<X509Certificate> chain) {
    }

    private final PkiProperties properties;

    public PkiMaterialStore(PkiProperties properties) {
        this.properties = properties;
    }

    public boolean exists(Kind kind) {
        return Files.isRegularFile(path(kind));
    }

    public boolean existsAll() {
        return Arrays.stream(Kind.values()).allMatch(this::exists);
    }

    public KeyMaterial load(Kind kind) {
        try {
            char[] password = properties.getStorePassword().toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(path(kind))) {
                keyStore.load(in, password);
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(kind.alias(), password);
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(kind.alias());
            Certificate[] rawChain = keyStore.getCertificateChain(kind.alias());
            List<X509Certificate> chain = Arrays.stream(rawChain)
                    .map(X509Certificate.class::cast)
                    .toList();

            return new KeyMaterial(privateKey, certificate, chain);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load PKI material: " + kind, e);
        }
    }

    public void write(
            Kind kind,
            PrivateKey privateKey,
            X509Certificate[] chain) {
        try {
            Files.createDirectories(properties.getBaseDir());
            char[] password = properties.getStorePassword().toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, password);
            keyStore.setKeyEntry(kind.alias(), privateKey, password, chain);
            try (OutputStream out = Files.newOutputStream(path(kind))) {
                keyStore.store(out, password);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to persist PKI material: " + kind, e);
        }
    }

    private Path path(Kind kind) {
        return properties.getBaseDir().resolve(kind.fileName());
    }
}
