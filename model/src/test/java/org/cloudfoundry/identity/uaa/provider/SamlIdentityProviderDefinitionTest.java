package org.cloudfoundry.identity.uaa.provider;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Test;

public class SamlIdentityProviderDefinitionTest {

    @Test
    public void test_that_serialized_json_does_not_contain_addNew() {
        SamlIdentityProviderDefinition samlDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation("mymetadata")
                .setLinkText("Test SAML Provider");
            samlDefinition.setAddNew(false);
            samlDefinition.setEmailDomain(Arrays.asList("test.com", "test2.com"));
        String config = JsonUtils.writeValueAsString(samlDefinition);
        Assert.assertTrue(config.contains("\"addShadowUserOnLogin\":false"));
        Assert.assertFalse(config.contains("addNew"));
    }

    @Test
    public void test_that_json_containing_addNew_is_deserialized() {
        String config = "{\"metaDataLocation\":\"mymetadata\",\"idpEntityAlias\":\"1D1DCE7769624FC0B8B8C11344EA67B8\"," 
                + "\"zoneId\":\"apm\",\"nameID\":\"unspecified\",\"assertionConsumerIndex\":0," 
                + "\"metadataTrustCheck\":false,\"showSamlLink\":false,\"socketFactoryClassName\":" 
                + "\"\",\"linkText\":\"Login with GE SSO staging\",\"iconUrl\":null,\"addNew\":false}";
        SamlIdentityProviderDefinition samlDefinition = JsonUtils.readValue(config, SamlIdentityProviderDefinition.class);
        Assert.assertFalse(samlDefinition.isAddShadowUserOnLogin());
    }
}
