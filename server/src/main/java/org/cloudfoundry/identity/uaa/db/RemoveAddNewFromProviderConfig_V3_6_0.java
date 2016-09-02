package org.cloudfoundry.identity.uaa.db;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

public class RemoveAddNewFromProviderConfig_V3_6_0 implements SpringJdbcMigration {

    private JdbcIdentityProviderProvisioning provisioning;
    public static final String SAML_IDENTITY_PROVIDER_WITH_DEPRECATED_PROPERTY_QUERY = "select "
            + JdbcIdentityProviderProvisioning.ID_PROVIDER_FIELDS + " from identity_provider where type='"
            + OriginKeys.SAML + "' and config like '%addNew%'";

    Log logger = LogFactory.getLog(RemoveAddNewFromProviderConfig_V3_6_0.class);

    @Override
    public void migrate(final JdbcTemplate jdbcTemplate) throws Exception {
        this.provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);

        logger.info("Starting migration to remove addNew property from SAML providers configuration.");
        List<IdentityProvider> providers = retrieveSamlProviders(jdbcTemplate);
        updateSamlProviders(jdbcTemplate, providers);
        logger.info(String.format("Completed migration. %d providers are updated.", providers.size()));
    }

    private void updateSamlProviders(final JdbcTemplate jdbcTemplate, final List<IdentityProvider> providers) {
        providers.forEach(provider -> this.provisioning.update(provider));
    }

    private List<IdentityProvider> retrieveSamlProviders(final JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.query(SAML_IDENTITY_PROVIDER_WITH_DEPRECATED_PROPERTY_QUERY, this.provisioning.mapper);
    }
}
