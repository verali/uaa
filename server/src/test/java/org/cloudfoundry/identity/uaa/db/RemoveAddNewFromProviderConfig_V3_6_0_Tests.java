package org.cloudfoundry.identity.uaa.db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.PreparedStatementSetter;

public class RemoveAddNewFromProviderConfig_V3_6_0_Tests extends JdbcTestBase {

    private JdbcIdentityProviderProvisioning provisioning;
    private RemoveAddNewFromProviderConfig_V3_6_0 migration;

    public static final String SAML_IDENTITY_PROVIDER_WITH_DEPRECATED_PROPERTY_COUNT = "select count(*) from identity_provider where type='"
            + OriginKeys.SAML + "' and config like '%addNew%'";
    public static final String SAML_IDENTITY_PROVIDER_TOTAL_COUNT = "select count(*) from identity_provider where type='"
            + OriginKeys.SAML + "'";

    @Before
    public void setUpMigration() {
        this.provisioning = new JdbcIdentityProviderProvisioning(this.jdbcTemplate);
        this.migration = new RemoveAddNewFromProviderConfig_V3_6_0();
    }

    @Test
    public void test_migration() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();

        // load Database
        // with Config with addNew Flag only
        String depricatedPropertyOnlyConfig = "{\"metaDataLocation\":\"mymetadata\",\"idpEntityAlias\":\"1D1DCE7769624FC0B8B8C11344EA67B8\","
                + "\"zoneId\":\"apm\",\"nameID\":\"unspecified\",\"assertionConsumerIndex\":0,"
                + "\"metadataTrustCheck\":false,\"showSamlLink\":false,\"socketFactoryClassName\":"
                + "\"\",\"linkText\":\"Login with GE SSO staging\",\"iconUrl\":null,\"addNew\":false}";
        this.provisionIdentityProvider(zoneId, "depricatedPropertyOnlyIdp", depricatedPropertyOnlyConfig);

        // load Database
        // with Config with addNew Flag and AddShadowUserOnLogin Flag
        String bothPropertiesConfig = "{\"metaDataLocation\":\"mymetadata\",\"idpEntityAlias\":\"1D1DCE7769624FC0B8B8C11344EA67B8\","
                + "\"zoneId\":\"apm\",\"nameID\":\"unspecified\",\"assertionConsumerIndex\":0,"
                + "\"metadataTrustCheck\":false,\"showSamlLink\":false,\"socketFactoryClassName\":"
                + "\"\",\"linkText\":\"Login with GE SSO staging\",\"iconUrl\":null,\"addNew\":false,\"addShadowUserOnLogin\":true}";
        this.provisionIdentityProvider(zoneId, "bothPropertiesIdp", bothPropertiesConfig);

        // load Database
        // with Config with AddShadowUserOnLogin Flag only
        String newPropertyOnlyConfig = "{\"metaDataLocation\":\"mymetadata\",\"idpEntityAlias\":\"1D1DCE7769624FC0B8B8C11344EA67B8\","
                + "\"zoneId\":\"apm\",\"nameID\":\"unspecified\",\"assertionConsumerIndex\":0,"
                + "\"metadataTrustCheck\":false,\"showSamlLink\":false,\"socketFactoryClassName\":"
                + "\"\",\"linkText\":\"Login with GE SSO staging\",\"iconUrl\":null,\"addShadowUserOnLogin\":true}";
        this.provisionIdentityProvider(zoneId, "newPropertyOnlyIdp", newPropertyOnlyConfig);

        // Check that Database is populated and that deprecated addNew flag is present
        assertEquals(this.jdbcTemplate.queryForObject(SAML_IDENTITY_PROVIDER_TOTAL_COUNT, Integer.class),
                new Integer(3));
        assertEquals(
                this.jdbcTemplate.queryForObject(SAML_IDENTITY_PROVIDER_WITH_DEPRECATED_PROPERTY_COUNT, Integer.class),
                new Integer(2));

        // Migrate
        this.migration.migrate(this.jdbcTemplate);

        // Check that the database is still populated and that the deprecated addNew flag has been removed
        assertEquals(this.jdbcTemplate.queryForObject(SAML_IDENTITY_PROVIDER_TOTAL_COUNT, Integer.class),
                new Integer(3));
        assertEquals(
                this.jdbcTemplate.queryForObject(SAML_IDENTITY_PROVIDER_WITH_DEPRECATED_PROPERTY_COUNT, Integer.class),
                new Integer(0));

        // Verify that new property was assigned
        assertFalse(((SamlIdentityProviderDefinition) this.provisioning
                .retrieveByOrigin("depricatedPropertyOnlyIdp", zoneId).getConfig()).isAddShadowUserOnLogin());
        assertTrue(((SamlIdentityProviderDefinition) this.provisioning.retrieveByOrigin("bothPropertiesIdp", zoneId)
                .getConfig()).isAddShadowUserOnLogin());
        assertTrue(((SamlIdentityProviderDefinition) this.provisioning.retrieveByOrigin("newPropertyOnlyIdp", zoneId)
                .getConfig()).isAddShadowUserOnLogin());
    }

    private IdentityProvider provisionIdentityProvider(final String zoneId, final String originKey,
            final String jsonConfig) {
        final String id = UUID.randomUUID().toString();
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zoneId);
        identityProvider.setType(OriginKeys.SAML);
        try {
            this.jdbcTemplate.update(JdbcIdentityProviderProvisioning.CREATE_IDENTITY_PROVIDER_SQL,
                    new PreparedStatementSetter() {
                        @Override
                        public void setValues(final PreparedStatement ps) throws SQLException {
                            int pos = 1;
                            ps.setString(pos++, id);
                            ps.setInt(pos++, identityProvider.getVersion());
                            ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                            ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                            ps.setString(pos++, identityProvider.getName());
                            ps.setString(pos++, identityProvider.getOriginKey());
                            ps.setString(pos++, identityProvider.getType());
                            ps.setString(pos++, jsonConfig);
                            ps.setString(pos++, identityProvider.getIdentityZoneId());
                            ps.setBoolean(pos++, identityProvider.isActive());
                        }
                    });
        } catch (DuplicateKeyException e) {
            throw new IdpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return this.provisioning.retrieve(id);
    }
}
