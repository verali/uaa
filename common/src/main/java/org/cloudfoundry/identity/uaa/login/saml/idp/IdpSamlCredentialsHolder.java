package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.springframework.security.core.Authentication;

public class IdpSamlCredentialsHolder {

    private final Authentication samlAuthenticationToken;
    private final Authentication openidAuthenticationToken;

    public IdpSamlCredentialsHolder(Authentication samlAuthenticationToken, Authentication openidAuthenticationToken) {
        this.samlAuthenticationToken = samlAuthenticationToken;
        this.openidAuthenticationToken = openidAuthenticationToken;
    }

    public Authentication getSamlAuthenticationToken() {
        return samlAuthenticationToken;
    }

    public Authentication getOpenidAuthenticationToken() {
        return openidAuthenticationToken;
    }
}
