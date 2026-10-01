package id.taufikiqbal.tte.signing;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;

class DssValidationPolicyRuntimeTest {

    @Test
    void defaultValidationPolicyIsAvailable() {
        assertNotNull(
                ValidationPolicyLoader
                        .fromDefaultValidationPolicy()
                        .create());
    }
}
