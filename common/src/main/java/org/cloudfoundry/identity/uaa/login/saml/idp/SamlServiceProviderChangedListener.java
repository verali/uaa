/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.login.saml.ZoneAwareMetadataManager;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.event.ServiceProviderModifiedEvent;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationListener;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class SamlServiceProviderChangedListener implements ApplicationListener<ServiceProviderModifiedEvent> {

    private static final Log logger = LogFactory.getLog(SamlServiceProviderChangedListener.class);
    private ZoneAwareMetadataManager metadataManager = null;
    private final SamlServiceProviderConfigurator configurator;
    private final IdentityZoneProvisioning zoneProvisioning;

    public SamlServiceProviderChangedListener(SamlServiceProviderConfigurator configurator,
            IdentityZoneProvisioning zoneProvisioning) {
        this.configurator = configurator;
        this.zoneProvisioning = zoneProvisioning;
    }

    @Override
    public void onApplicationEvent(ServiceProviderModifiedEvent event) {
        if (metadataManager == null) {
            return;
        }
        SamlServiceProvider changedSamlServiceProvider = (SamlServiceProvider) event.getSource();
        IdentityZone zone = zoneProvisioning.retrieve(changedSamlServiceProvider.getIdentityZoneId());
        ZoneAwareMetadataManager.ExtensionMetadataManager manager = metadataManager.getManager(zone);
        SamlServiceProviderDefinition definition = ObjectUtils.castInstance(changedSamlServiceProvider.getConfig(),
                SamlServiceProviderDefinition.class);
        try {
            if (changedSamlServiceProvider.isActive()) {
                ExtendedMetadataDelegate[] delegates = configurator.addSamlServiceProviderDefinition(definition);
                if (delegates[1] != null) {
                    manager.removeMetadataProvider(delegates[1]);
                }
                manager.addMetadataProvider(delegates[0]);
            } else {
                ExtendedMetadataDelegate delegate = configurator.removeServiceProviderDefinition(definition);
                if (delegate != null) {
                    manager.removeMetadataProvider(delegate);
                }
            }
            for (MetadataProvider provider : manager.getProviders()) {
                provider.getMetadata();
            }
            manager.refreshMetadata();
            metadataManager.getManager(zone).refreshMetadata();
        } catch (MetadataProviderException e) {
            logger.error("Unable to add new SAML service provider:" + definition, e);
        }
    }

    public void setMetadataManager(ZoneAwareMetadataManager metadataManager) {
        this.metadataManager = metadataManager;
    }
}
