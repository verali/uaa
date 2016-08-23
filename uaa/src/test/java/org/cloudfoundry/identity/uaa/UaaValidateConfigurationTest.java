package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration;
import org.junit.Test;

public class UaaValidateConfigurationTest {

    @Test
    public void validateUaaConfiguration() throws Exception {
        assertTrue(UaaConfiguration
                .validateConfiguration(System.getProperty("user.dir") + "/src/main/resources/uaa.yml").isEmpty());
    }

}
