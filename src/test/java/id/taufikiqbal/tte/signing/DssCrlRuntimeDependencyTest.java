package id.taufikiqbal.tte.signing;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

class DssCrlRuntimeDependencyTest {

    @Test
    void crlParserImplementationIsAvailable() {
        assertDoesNotThrow(() ->
                Class.forName(
                        "eu.europa.esig.dss.crl.CRLUtils",
                        true,
                        DssCrlRuntimeDependencyTest.class.getClassLoader()));
    }
}
