package id.taufikiqbal.tte.signing;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.utils.Utils;

class DssRuntimeDependencyTest {

    @Test
    void dssUtilityImplementationIsAvailable() {
        assertTrue(Utils.isStringNotBlank("dss-runtime-ready"));
    }
}
