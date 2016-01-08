package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLAuthenticationToken;

public class IdpSAMLAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication openidAuthenticationToken = securityContext.getAuthentication();

        IdpSamlCredentialsHolder credentials = new IdpSamlCredentialsHolder(authentication, openidAuthenticationToken);

        return new IdpSamlAuthentication(credentials);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SAMLAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
