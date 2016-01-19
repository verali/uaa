package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public interface IdpWebSsoProfile {

    void sendResponse(Authentication authentication, SAMLMessageContext context, WebSSOProfileOptions options)
            throws SAMLException, MetadataProviderException, MessageEncodingException;
}
