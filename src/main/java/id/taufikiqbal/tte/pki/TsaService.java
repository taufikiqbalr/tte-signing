package id.taufikiqbal.tte.pki;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import id.taufikiqbal.tte.config.PkiProperties;
import id.taufikiqbal.tte.pki.PkiMaterialStore.KeyMaterial;
import id.taufikiqbal.tte.pki.PkiMaterialStore.Kind;

@Service
public class TsaService {

    private static final Logger log =
            LoggerFactory.getLogger(TsaService.class);

    private final PkiProperties properties;
    private final PkiMaterialStore materialStore;
    private final CertificateRepository repository;

    public TsaService(
            PkiProperties properties,
            PkiMaterialStore materialStore,
            CertificateRepository repository) {
        this.properties = properties;
        this.materialStore = materialStore;
        this.repository = repository;
    }

    public byte[] timestamp(byte[] requestBytes) {
        log.info(
                "RFC3161 timestamp request received bytes={}",
                requestBytes == null ? 0 : requestBytes.length);
        try {
            TimeStampRequest request = new TimeStampRequest(requestBytes);
            KeyMaterial tsa = materialStore.load(Kind.TSA);

            DigestCalculatorProvider calculators =
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider("BC")
                            .build();
            DigestCalculator certDigest = calculators.get(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

            ContentSigner contentSigner =
                    new JcaContentSignerBuilder("SHA384withRSA")
                            .setProvider("BC")
                            .build(tsa.privateKey());
            SignerInfoGenerator signerInfo =
                    new JcaSignerInfoGeneratorBuilder(calculators)
                            .build(contentSigner, tsa.certificate());

            ASN1ObjectIdentifier policyOid =
                    new ASN1ObjectIdentifier(properties.getTsaPolicyOid());
            TimeStampTokenGenerator tokenGenerator =
                    new TimeStampTokenGenerator(
                            signerInfo, certDigest, policyOid, true);
            tokenGenerator.addCertificates(
                    new JcaCertStore(List.copyOf(tsa.chain())));
            tokenGenerator.setAccuracySeconds(
                    properties.getTsaAccuracySeconds());
            tokenGenerator.setOrdering(false);
            tokenGenerator.setTSA(new GeneralName(
                    new JcaX509CertificateHolder(tsa.certificate()).getSubject()));

            Set<ASN1ObjectIdentifier> acceptedAlgorithms = Set.of(
                    TSPAlgorithms.SHA256,
                    TSPAlgorithms.SHA384,
                    TSPAlgorithms.SHA512);
            Set<ASN1ObjectIdentifier> acceptedPolicies = Set.of(policyOid);

            TimeStampResponseGenerator responseGenerator =
                    new TimeStampResponseGenerator(
                            tokenGenerator,
                            acceptedAlgorithms,
                            acceptedPolicies);

            Instant now = Instant.now();
            TimeStampResponse response;
            try {
                response = responseGenerator.generateGrantedResponse(
                        request,
                        repository.nextTsaSerial(),
                        Date.from(now),
                        "granted");
            } catch (TSPException rejected) {
                log.warn(
                        "RFC3161 timestamp request rejected policyOid={} reason={}",
                        properties.getTsaPolicyOid(),
                        rejected.getMessage(),
                        rejected);
                response = responseGenerator.generateRejectedResponse(rejected);
            }

            byte[] encoded = response.getEncoded();
            log.info(
                    "RFC3161 timestamp response generated status={} bytes={}",
                    response.getStatus(),
                    encoded.length);
            return encoded;
        } catch (Exception e) {
            log.error(
                    "RFC3161 timestamp processing failed bytes={} exceptionType={} message={}",
                    requestBytes == null ? 0 : requestBytes.length,
                    e.getClass().getName(),
                    e.getMessage(),
                    e);
            throw new IllegalArgumentException(
                    "Invalid or unsupported RFC 3161 timestamp request", e);
        }
    }
}
