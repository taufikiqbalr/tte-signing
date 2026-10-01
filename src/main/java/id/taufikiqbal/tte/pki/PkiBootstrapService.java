package id.taufikiqbal.tte.pki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Component
public class PkiBootstrapService implements ApplicationRunner {

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateAuthorityService certificateAuthorityService;

    public PkiBootstrapService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateAuthorityService certificateAuthorityService) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.certificateAuthorityService = certificateAuthorityService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isBootstrapEnabled()) {
            return;
        }
        if (materialStore.existsAll()) {
            return;
        }

        long existing = Arrays.stream(Kind.values())
                .filter(materialStore::exists)
                .count();
        if (existing != 0) {
            throw new IllegalStateException(
                    "Partial PKI material detected. Refusing to overwrite keys. "
                    + "Restore the complete PKI set or use a clean development directory.");
        }

        requireBootstrapConfiguration();

        KeyPair rootKeyPair = certificateAuthorityService.generateKeyPair();
        X509Certificate rootCertificate =
                certificateAuthorityService.createRootCertificate(rootKeyPair);
        materialStore.write(
                Kind.ROOT,
                rootKeyPair.getPrivate(),
                new X509Certificate[] {rootCertificate});

        KeyMaterial root = materialStore.load(Kind.ROOT);
        KeyPair issuerKeyPair = certificateAuthorityService.generateKeyPair();
        X509Certificate issuerCertificate =
                certificateAuthorityService.createIssuingCaCertificate(
                        issuerKeyPair, root);
        materialStore.write(
                Kind.ISSUING,
                issuerKeyPair.getPrivate(),
                new X509Certificate[] {issuerCertificate, rootCertificate});

        KeyMaterial issuer = materialStore.load(Kind.ISSUING);
        KeyPair ocspKeyPair = certificateAuthorityService.generateKeyPair();
        X509Certificate ocspCertificate =
                certificateAuthorityService.createOcspResponderCertificate(
                        ocspKeyPair, issuer);
        materialStore.write(
                Kind.OCSP,
                ocspKeyPair.getPrivate(),
                new X509Certificate[] {
                        ocspCertificate, issuerCertificate, rootCertificate
                });

        KeyPair tsaKeyPair = certificateAuthorityService.generateKeyPair();
        X509Certificate tsaCertificate =
                certificateAuthorityService.createTsaCertificate(
                        tsaKeyPair, issuer);
        materialStore.write(
                Kind.TSA,
                tsaKeyPair.getPrivate(),
                new X509Certificate[] {
                        tsaCertificate, issuerCertificate, rootCertificate
                });
    }

    private void requireBootstrapConfiguration() {
        if (isBlank(properties.getStorePassword())
                || isBlank(properties.getRootSubject())
                || isBlank(properties.getIssuingSubject())
                || isBlank(properties.getOcspSubject())
                || isBlank(properties.getTsaSubject())
                || isBlank(properties.getTsaPolicyOid())) {
            throw new IllegalStateException(
                    "PKI bootstrap configuration is incomplete");
        }
        if (properties.getStorePassword().length() < 16) {
            throw new IllegalStateException(
                    "PKI store password must be at least 16 characters");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
