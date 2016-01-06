package org.cloudfoundry.identity.uaa.login.saml.idp;

import java.util.List;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;

public class IdpMetadataManager extends MetadataManager {

    private String hostedIdpName;

    public IdpMetadataManager(final List<MetadataProvider> providers) throws MetadataProviderException {
        super(providers);
    }

    public String getHostedIdpName() {
        return this.hostedIdpName;
    }

    public void setHostedIdpName(final String hostedIdpName) {
        this.hostedIdpName = hostedIdpName;
    }
}
