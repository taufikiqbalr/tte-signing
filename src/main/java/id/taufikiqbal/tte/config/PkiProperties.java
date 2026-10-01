package id.taufikiqbal.tte.config;

import java.nio.file.Path;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pki")
public class PkiProperties {

    private Path baseDir = Path.of("./data/pki");
    private String publicBaseUrl = "http://localhost:8088";
    private boolean bootstrapEnabled = true;
    private String storePassword = "change-this-pki-store-password";
    private String rootSubject = "CN=TTE Development Root CA,O=TTE Private PKI,C=ID";
    private String issuingSubject = "CN=TTE Development Issuing CA,O=TTE Private PKI,C=ID";
    private String ocspSubject = "CN=TTE Development OCSP Responder,O=TTE Private PKI,C=ID";
    private String tsaSubject = "CN=TTE Development TSA,O=TTE Private PKI,C=ID";
    private int rootValidityDays = 3650;
    private int issuerValidityDays = 1825;
    private int serviceValidityDays = 825;
    private int endEntityValidityDays = 365;
    private int maxEndEntityValidityDays = 825;
    private int ocspValidityMinutes = 30;
    private int crlValidityHours = 24;
    private String tsaPolicyOid = "1.3.6.1.4.1.55555.1.1";
    private int tsaAccuracySeconds = 1;

    public Path getBaseDir() { return baseDir; }
    public void setBaseDir(Path baseDir) { this.baseDir = baseDir; }
    public String getPublicBaseUrl() { return publicBaseUrl; }
    public void setPublicBaseUrl(String publicBaseUrl) { this.publicBaseUrl = stripTrailingSlash(publicBaseUrl); }
    public boolean isBootstrapEnabled() { return bootstrapEnabled; }
    public void setBootstrapEnabled(boolean bootstrapEnabled) { this.bootstrapEnabled = bootstrapEnabled; }
    public String getStorePassword() { return storePassword; }
    public void setStorePassword(String storePassword) { this.storePassword = storePassword; }
    public String getRootSubject() { return rootSubject; }
    public void setRootSubject(String rootSubject) { this.rootSubject = rootSubject; }
    public String getIssuingSubject() { return issuingSubject; }
    public void setIssuingSubject(String issuingSubject) { this.issuingSubject = issuingSubject; }
    public String getOcspSubject() { return ocspSubject; }
    public void setOcspSubject(String ocspSubject) { this.ocspSubject = ocspSubject; }
    public String getTsaSubject() { return tsaSubject; }
    public void setTsaSubject(String tsaSubject) { this.tsaSubject = tsaSubject; }
    public int getRootValidityDays() { return rootValidityDays; }
    public void setRootValidityDays(int rootValidityDays) { this.rootValidityDays = rootValidityDays; }
    public int getIssuerValidityDays() { return issuerValidityDays; }
    public void setIssuerValidityDays(int issuerValidityDays) { this.issuerValidityDays = issuerValidityDays; }
    public int getServiceValidityDays() { return serviceValidityDays; }
    public void setServiceValidityDays(int serviceValidityDays) { this.serviceValidityDays = serviceValidityDays; }
    public int getEndEntityValidityDays() { return endEntityValidityDays; }
    public void setEndEntityValidityDays(int endEntityValidityDays) { this.endEntityValidityDays = endEntityValidityDays; }
    public int getMaxEndEntityValidityDays() { return maxEndEntityValidityDays; }
    public void setMaxEndEntityValidityDays(int maxEndEntityValidityDays) { this.maxEndEntityValidityDays = maxEndEntityValidityDays; }
    public int getOcspValidityMinutes() { return ocspValidityMinutes; }
    public void setOcspValidityMinutes(int ocspValidityMinutes) { this.ocspValidityMinutes = ocspValidityMinutes; }
    public int getCrlValidityHours() { return crlValidityHours; }
    public void setCrlValidityHours(int crlValidityHours) { this.crlValidityHours = crlValidityHours; }
    public String getTsaPolicyOid() { return tsaPolicyOid; }
    public void setTsaPolicyOid(String tsaPolicyOid) { this.tsaPolicyOid = tsaPolicyOid; }
    public int getTsaAccuracySeconds() { return tsaAccuracySeconds; }
    public void setTsaAccuracySeconds(int tsaAccuracySeconds) { this.tsaAccuracySeconds = tsaAccuracySeconds; }

    private static String stripTrailingSlash(String value) {
        if (value == null) return null;
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
