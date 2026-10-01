package id.taufikiqbal.tte.pki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.springframework.boot.ApplicationArguments;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Component
public class PkiBootstrapService implements ApplicationRunner {

    private static final Logger log =
            LoggerFactory.getLogger(PkiBootstrapService.class);

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateAuthorityService certificateAuthorityService;
    private final CertificateRepository certificateRepository;

    public PkiBootstrapService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateAuthorityService certificateAuthorityService,
            CertificateRepository certificateRepository) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.certificateAuthorityService = certificateAuthorityService;
        this.certificateRepository = certificateRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isBootstrapEnabled()) {
            return;
        }
        if (materialStore.existsAll()) {
            synchronizeServiceCertificates();
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

        synchronizeServiceCertificates();
    }

    private void synchronizeServiceCertificates() {
        X509Certificate ocspCertificate =
                materialStore.load(Kind.OCSP).certificate();
        X509Certificate tsaCertificate =
                materialStore.load(Kind.TSA).certificate();

        certificateRepository.saveIfAbsent(ocspCertificate);
        certificateRepository.saveIfAbsent(tsaCertificate);

        log.info(
                "PKI service certificates synchronized ocspSerial={} tsaSerial={}",
                ocspCertificate.getSerialNumber().toString(16).toUpperCase(),
                tsaCertificate.getSerialNumber().toString(16).toUpperCase());
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
