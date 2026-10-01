package id.taufikiqbal.tte.signing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.cms.CMSGenerator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class DssRuntimeVerifier implements ApplicationRunner {

    private static final Logger log =
            LoggerFactory.getLogger(DssRuntimeVerifier.class);

    @Override
    public void run(ApplicationArguments args) {
        try {
            if (!Utils.isStringNotBlank("dss-runtime-check")) {
                throw new IllegalStateException(
                        "DSS utility provider returned an unexpected result");
            }

            Object cmsGenerator = CMSGenerator.loadCMSGenerator();
            if (cmsGenerator == null) {
                throw new IllegalStateException(
                        "DSS CMSGenerator provider is unavailable");
            }

            Object validationPolicy = ValidationPolicyLoader
                    .fromDefaultValidationPolicy()
                    .create();
            if (validationPolicy == null) {
                throw new IllegalStateException(
                        "DSS default validation policy provider is unavailable");
            }

            Class.forName(
                    "eu.europa.esig.dss.crl.CRLUtils",
                    true,
                    DssRuntimeVerifier.class.getClassLoader());

            log.info(
                    "DSS runtime providers verified utilityProvider=true cmsGenerator={} validationPolicy={} crlParser=true",
                    cmsGenerator.getClass().getName(),
                    validationPolicy.getClass().getName());
        } catch (Throwable failure) {
            log.error(
                    "DSS runtime provider verification failed exceptionType={} message={}",
                    failure.getClass().getName(),
                    failure.getMessage(),
                    failure);
            throw new IllegalStateException(
                    "DSS runtime dependencies are incomplete. "
                    + "Verify dss-utils-apache-commons, dss-cms-object, "
                    + "dss-policy-jaxb, and dss-crl-parser-x509crl.",
                    failure);
        }
    }
}
