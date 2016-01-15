/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.login.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginWithLocalIdpIT {

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();

    @Before
    public void clearWebDriverOfCookies() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone2.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
        webDriver.get("http://simplesamlphp2.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    /**
     * Test that can UAA generate it's own SAML identity provider metadata.
     */
    @Test
    public void testDownloadSamlIdpMetadata() {
        String entityId = "unit-test-idp";
        SamlIdentityProviderDefinition idpDefinition = createLocalSamlIDP(entityId, "uaa");
        Assert.assertTrue(idpDefinition.getMetaDataLocation().contains(IDPSSODescriptor.DEFAULT_ELEMENT_LOCAL_NAME));
        Assert.assertTrue(idpDefinition.getMetaDataLocation().contains("entityID=\"" + entityId + "\""));
    }

    /**
     * Test that we can create an identity provider in UAA using UAA's own SAML identity provider metadata.
     */
    @Test
    public void testCreateSamlIdp() throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIDP("unit-test-idp", "uaa");
        IntegrationTestUtils.createIdentityProvider("Local SAML IdP", "unit-test-idp", true, this.baseUrl,
                this.serverRunning, idpDef);
    }

    public static SamlIdentityProviderDefinition createLocalSamlIDP(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/" + zoneId + "." + alias + "/idp";
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias + "/idp";
        }

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        String idpMetaData = metadataResponse.getBody();
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            def.setIdpEntityAlias(zoneId + "." + alias);
            def.setLinkText("Login with Local SAML IdP(" + zoneId + "." + alias + ")");
        } else {
            def.setIdpEntityAlias(alias);
            def.setLinkText("Login with Local SAML IdP(" + alias + ")");
        }
        return def;
    }

    @Test
    public void testCreateSamlSp() throws Exception {
        SamlServiceProviderDefinition spDef = createLocalSamlSP("cloudfoundry-saml-login", "uaa");
        createSamlServiceProvider("Local SAML SP", "unit-test-sp", baseUrl, serverRunning, spDef);
    }

    public static SamlServiceProviderDefinition createLocalSamlSP(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/" + zoneId + "." + alias;
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias;
        }

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        String spMetaData = metadataResponse.getBody();
        SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
        def.setZoneId(zoneId);
        def.setSpEntityId(alias);
        def.setMetaDataLocation(spMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setSingleSignOnServiceIndex(0);
        def.setMetadataTrustCheck(false);
        return def;
    }

    public static SamlServiceProvider createSamlServiceProvider(String name, String entityId, String baseUrl,
            ServerRunning serverRunning, SamlServiceProviderDefinition samlServiceProviderDefinition) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret"));
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), Origin.UAA);

        String zoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", email, "secr3T");

        SamlServiceProvider provider = new SamlServiceProvider();
        provider.setConfig(samlServiceProviderDefinition);
        provider.setIdentityZoneId(Origin.UAA);
        provider.setActive(true);
        provider.setEntityId(samlServiceProviderDefinition.getSpEntityId());
        provider.setName(name);
        provider = createOrUpdateSamlServiceProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public static SamlServiceProvider createOrUpdateSamlServiceProvider(String accessToken, String url,
            SamlServiceProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<SamlServiceProvider> existing = getSamlServiceProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (SamlServiceProvider p : existing) {
                if (p.getEntityId().equals(provider.getEntityId())
                        && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity<SamlServiceProvider> putHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(url + "/service-providers/{id}",
                            HttpMethod.PUT, putHeaders, String.class, provider.getId());
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), SamlServiceProvider.class);
                    }
                }
            }
        }

        HttpEntity<SamlServiceProvider> postHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(url + "/service-providers/{id}", HttpMethod.POST,
                postHeaders, String.class, provider.getId());
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), SamlServiceProvider.class);
        }
        throw new IllegalStateException(
                "Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }

    public static List<SamlServiceProvider> getSamlServiceProviders(String zoneAdminToken, String url, String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> providerGet = client.exchange(url + "/service-providers", HttpMethod.GET, getHeaders,
                String.class);
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<SamlServiceProvider>>() {
                // Do nothing.
            });
        }
        return null;
    }

    // @Test
    public void failureResponseFromSamlIDP_showErrorFromSaml() throws Exception {
        assumeTrue("Expected testzone1/2/3.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");

        // identity client token
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(baseUrl,
                        new String[] { "zones.write", "zones.read", "scim.zones" }, "identity", "identitysecret"));
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        // create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);

        // create a zone admin user
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        // get the zone admin token
        String zoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", email, "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone3IDP("unit-test-idp");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(Origin.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone3");

        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        webDriver.get(zoneUrl);
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + zoneId + "]!')]"));
        webDriver.findElement(By.linkText("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"))
                .click();
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertEquals("No local entity found for alias invalid, verify your configuration.",
                webDriver.findElement(By.cssSelector("h2")).getText());
    }

    @Test
    public void testLocalSamlIdpLogin() throws Exception {
        testLocalSamlIdpLogin("/login", "Where to?", "marissa", "koala");
    }

    private void testLocalSamlIdpLogin(String firstUrl, String lookfor, String username, String password)
            throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIDP("unit-test-idp", "uaa");
        @SuppressWarnings("unchecked")
        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(
                "Local SAML IdP", "unit-test-idp", true, this.baseUrl, this.serverRunning, idpDef);

        // tells us that we are on travis
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());

        webDriver.get(baseUrl + firstUrl);
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString(lookfor));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testLocalSamlIdpLoginInTestZone1Works() throws Exception {
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";

        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(baseUrl,
                        new String[] { "zones.write", "zones.read", "scim.zones" }, "identity", "identitysecret"));
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        String zoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", email, "secr3T");

        String testZone1Url = baseUrl.replace("localhost", zoneId + ".localhost");
        String zoneAdminClientId = new RandomValueStringGenerator().generate() + "-" + zoneId + "-admin";
        BaseClientDetails clientDetails = new BaseClientDetails(zoneAdminClientId, null, "uaa.none",
                "client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", testZone1Url);
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(testZone1Url, new String[0], zoneAdminClientId, "secret"));
        String zoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        IntegrationTestUtils.createUser(zoneAdminClient, testZone1Url, zoneUserEmail, "Dana", "Scully", zoneUserEmail,
                true);

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP("unit-test-idp");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(Origin.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("Local SAML IdP for testzone1");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());

        List<WebElement> elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());

        WebElement element = elements.get(0);
        assertNotNull(element);
        element.click();
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + zoneId + "]!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(zoneUserEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");

        // disable the provider
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        // enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(),
                    new byte[] { 127, 0, 0, 1 })
                    && Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(),
                            new byte[] { 127, 0, 0, 1 })
                    && Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(),
                            new byte[] { 127, 0, 0, 1 });
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createLocalSamlIDP(alias, "testzone1");
    }

    public SamlIdentityProviderDefinition createTestZone2IDP(String alias) {
        return createLocalSamlIDP(alias, "testzone2");
    }

    public SamlIdentityProviderDefinition createTestZone3IDP(String alias) {
        return createLocalSamlIDP(alias, "testzone3");
    }
}
