package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLAuthenticationToken;

public class IdpSAMLAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SAMLAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
