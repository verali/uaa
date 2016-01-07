package org.cloudfoundry.identity.uaa.login.saml.idp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

public class IdpSAMLAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private IdpWebSSOProfile idpWebSSOProfile;
    private MetadataManager metadata;

    public IdpSAMLAuthenticationSuccessHandler() {
        super();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageContext context = token.getCredentials();
        try {
            populatePeerContext(context);
        } catch (MetadataProviderException e) {
            throw new ServletException("Failed to populate peer SAML context.", e);
        }

        // TODO: Review error handler of success handler for SAML processing filter.
        try {
            WebSSOProfileOptions options = new WebSSOProfileOptions();
            idpWebSSOProfile.sendResponse(context, options);
        } catch (SAMLException e) {
            //logger.debug("Incoming SAML message is invalid", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid.", e);
        } catch (MetadataProviderException e) {
            //logger.debug("Error determining metadata contracts", e);
            throw new AuthenticationServiceException("Error determining metadata contracts.", e);
        } catch (MessageEncodingException e) {
            //logger.debug("Error decoding incoming SAML message", e);
            throw new AuthenticationServiceException("Error encoding outgoing SAML message.", e);
        }
    }

    protected void populatePeerContext(SAMLMessageContext samlContext) throws MetadataProviderException {

        String peerEntityId = samlContext.getPeerEntityId();
        QName peerEntityRole = samlContext.getPeerEntityRole();

        if (peerEntityId == null) {
            throw new MetadataProviderException("Peer entity ID wasn't specified, but is requested");
        }

        EntityDescriptor entityDescriptor = metadata.getEntityDescriptor(peerEntityId);
        RoleDescriptor roleDescriptor = metadata.getRole(peerEntityId, peerEntityRole, SAMLConstants.SAML20P_NS);
        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(peerEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException("Metadata for entity " + peerEntityId + " and role " + peerEntityRole + " wasn't found");
        }

        samlContext.setPeerEntityMetadata(entityDescriptor);
        samlContext.setPeerEntityRoleMetadata(roleDescriptor);
        samlContext.setPeerExtendedMetadata(extendedMetadata);
    }

    @Autowired
    public void setIdpWebSSOProfile(IdpWebSSOProfile idpWebSSOProfile) {
        Assert.notNull(idpWebSSOProfile, "SAML web sso profile can't be null.");
        this.idpWebSSOProfile = idpWebSSOProfile;
    }

    @Autowired
    public void setMetadata(MetadataManager metadata) {
        Assert.notNull(metadata, "SAML metadata manager can't be null.");
        this.metadata = metadata;
    }
}
