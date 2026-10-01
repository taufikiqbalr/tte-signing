package id.taufikiqbal.tte.pki;

import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

public class PrivatePkiTrustedCertificateSource
        extends CommonTrustedCertificateSource {

    private static final long serialVersionUID = 1L;

    private final String rootCrlUrl;

    public PrivatePkiTrustedCertificateSource(String rootCrlUrl) {
        this.rootCrlUrl = rootCrlUrl;
    }

    @Override
    public List<String> getAlternativeCRLUrls(
            CertificateToken trustAnchor) {
        if (rootCrlUrl == null || rootCrlUrl.isBlank()) {
            return List.of();
        }
        return List.of(rootCrlUrl);
    }
}
