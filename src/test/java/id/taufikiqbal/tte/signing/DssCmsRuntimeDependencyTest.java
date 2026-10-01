package id.taufikiqbal.tte.signing;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cms.CMSGenerator;

class DssCmsRuntimeDependencyTest {

    @Test
    void cmsGeneratorImplementationIsAvailable() {
        assertNotNull(CMSGenerator.loadCMSGenerator());
    }
}
