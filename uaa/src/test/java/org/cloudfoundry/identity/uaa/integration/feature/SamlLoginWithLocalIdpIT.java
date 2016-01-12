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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.config.LockoutPolicy;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.logging.LogEntry;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginWithLocalIdpIT {

    @Autowired @Rule
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

    ObjectMapper objectMapper = new ObjectMapper();

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
        Assert.assertTrue(idpDefinition.getMetaDataLocation().contains("entityID=\"" + entityId +"\""));
    }

    /**
     * Test that we can create an identity provider in UAA using UAA's own SAML identity provider metadata.
     */
    @Test
    public void testCreateSamlIdp() throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIDP("unit-test-idp", "uaa");
        IntegrationTestUtils.createIdentityProvider("Local SAML IdP", "unit-test-idp", true, this.baseUrl, this.serverRunning, idpDef);
    }

    public static SamlIdentityProviderDefinition createLocalSamlIDP(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/"
                    + zoneId + "." + alias + "/idp";
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias + "/idp";
        }

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(
            url,
            HttpMethod.GET,
            getHeaders,
            String.class
        );

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

    //@Test
    public void testSimpleSamlLoginWithAddShadowUserOnLoginFalse() throws Exception {
        // Deleting marissa@test.org from simplesamlphp because previous SAML authentications automatically
        // create a UAA user with the email address as the username.
        deleteUser("simplesamlphp", testAccounts.getEmail());

        IdentityProvider provider = IntegrationTestUtils.createIdentityProvider("simplesamlphp", false, baseUrl, serverRunning);
        String clientId = "app-addnew-false"+ new RandomValueStringGenerator().generate();
        String redirectUri = "http://nosuchhostname:0/nosuchendpoint";
        BaseClientDetails client = createClientAndSpecifyProvider(clientId, provider, redirectUri);

        //tells us that we are on travis
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());

        String firstUrl = "/oauth/authorize?"
                + "client_id=" + clientId
                + "&response_type=code"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8");

        webDriver.get(baseUrl + firstUrl);
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        // We need to verify the last request URL through the HTTP Archive (HAR) log because the redirect
        // URI does not exist. When the webDriver follows the non-existent redirect URI it receives a
        // connection refused error so webDriver.getCurrentURL() will remain as the SAML IdP URL.
        Thread.sleep(1000);
        List<LogEntry> harLogEntries = webDriver.manage().logs().get("har").getAll();
        LogEntry lastLogEntry = harLogEntries.get(harLogEntries.size() - 1);

        String lastRequestUrl = getRequestUrlFromHarLogEntry(lastLogEntry);

        assertThat("Unexpected URL.", lastRequestUrl,
                Matchers.containsString(redirectUri + "?error=access_denied"
                        + "&error_description=SAML+user+does+not+exist.+You+can+correct+this+by+creating+a+shadow+user+for+the+SAML+user."));
    }

    //@Test
    public void failureResponseFromSamlIDP_showErrorFromSaml() throws Exception {
        assumeTrue("Expected testzone1/2/3.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createLocalSamlIDP("simplesamlphp", "testzone3");
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(Origin.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone2");

        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);

        webDriver.get(zoneUrl);
        webDriver.findElement(By.linkText("Login with Simple SAML PHP(simplesamlphp)")).click();
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertEquals("No local entity found for alias invalid, verify your configuration.", webDriver.findElement(By.cssSelector("h2")).getText());
    }

    private String getRequestUrlFromHarLogEntry(LogEntry logEntry)
            throws IOException, JsonParseException, JsonMappingException {

        Map<String, Object> message = this.objectMapper.readValue(logEntry.getMessage(), Map.class);
        Map<String, Object> log = (Map<String, Object>) message.get("log");
        List<Object> entries = (List<Object>) log.get("entries");
        Map<String, Object> lastEntry = (Map<String, Object>) entries.get(entries.size() - 1);
        Map<String, Object> request = (Map<String, Object>) lastEntry.get("request");
        String url = (String) request.get("url");
        return url;
    }

    @Test
    public void testLocalSamlIdpLogin() throws Exception {
        testLocalSamlIdpLogin("/login", "Where to?", "marissa", "koala");
    }

    private void testLocalSamlIdpLogin(String firstUrl, String lookfor, String username, String password) throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIDP("unit-test-idp", "uaa");
        IdentityProvider<SamlIdentityProviderDefinition> provider =
                IntegrationTestUtils.createIdentityProvider("Local SAML IdP", "unit-test-idp", true, this.baseUrl, this.serverRunning, idpDef);

        //tells us that we are on travis
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());

        webDriver.get(baseUrl + firstUrl);
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        IntegrationTestUtils.takeScreenShot(webDriver);
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        IntegrationTestUtils.takeScreenShot(webDriver);
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString(lookfor));
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) throws Exception {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning);
    }

    protected BaseClientDetails createClientAndSpecifyProvider(String clientId, IdentityProvider provider,
            String redirectUri)
            throws Exception {

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), Origin.UAA);

        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid",
                "authorization_code", "uaa.resource", redirectUri);
        clientDetails.setClientSecret("secret");
        List<String> idps = Arrays.asList(provider.getOriginKey());
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);
        IntegrationTestUtils.createClient(zoneAdminToken, baseUrl, clientDetails);

        return clientDetails;
    }

    protected void deleteUser(String origin, String username)
            throws Exception {

        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning,
                                                                               "admin", "adminsecret");

        String userId = IntegrationTestUtils.getUserId(zoneAdminToken, baseUrl, origin, username);
        if (null == userId) {
            return;
        }

        IntegrationTestUtils.deleteUser(zoneAdminToken, baseUrl, userId);
    }

    //@Test
    public void test_SamlInvitation_Automatic_Redirect_In_Zone2() throws Exception {
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);

        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
    }

    public void perform_SamlInvitation_Automatic_Redirect_In_Zone2(String username, String password, boolean emptyList) throws Exception {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone2IDP("simplesamlphp");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(Origin.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone2");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        UaaIdentityProviderDefinition uaaDefinition = new UaaIdentityProviderDefinition(
            new PasswordPolicy(1,255,0,0,0,0,12),
            new LockoutPolicy(10, 10, 10)
        );
        uaaDefinition.setEmailDomain(emptyList ? Collections.EMPTY_LIST : Arrays.asList("*.*","*.*.*"));
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = IntegrationTestUtils.getProvider(zoneAdminToken, baseUrl, zoneId, Origin.UAA);
        uaaProvider.setConfig(uaaDefinition);
        uaaProvider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,uaaProvider);

        BaseClientDetails uaaAdmin = new BaseClientDetails("admin","","", "client_credentials","uaa.admin,scim.read,scim.write");
        uaaAdmin.setClientSecret("adminsecret");
        IntegrationTestUtils.createOrUpdateClient(zoneAdminToken, baseUrl, zoneId, uaaAdmin);

        String uaaAdminToken = testClient.getOAuthAccessToken(zoneUrl, "admin", "adminsecret", "client_credentials", "");

        String useremail = username + "@test.org";
        String code = InvitationsIT.createInvitation(zoneUrl, zoneUrl, useremail, useremail, samlIdentityProviderDefinition.getIdpEntityAlias(), "", uaaAdminToken, uaaAdminToken);
        String invitedUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        String existingUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/invitations/accept?code=" + code);

        //redirected to saml login
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        //we should now be on the login page because we don't have a redirect
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        uaaProvider.setConfig((UaaIdentityProviderDefinition) uaaDefinition.setEmailDomain(null));
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,uaaProvider);

        String acceptedUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        if (StringUtils.isNotEmpty(existingUserId)) {
            assertEquals(acceptedUserId, existingUserId);
        } else {
            assertEquals(invitedUserId, acceptedUserId);
        }

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    protected boolean isMember(String userId, ScimGroup group) {
        for (ScimGroupMember member : group.getMembers()) {
            if(userId.equals(member.getMemberId())) {
                return true;
            }
        }
        return false;
    }

    //@Test
    public void testSamlLoginClientIDPAuthorizationAutomaticRedirectInZone1() throws Exception {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP("simplesamlphp");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(Origin.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        List<String> idps = Arrays.asList(provider.getOriginKey());
        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.none", baseUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);
        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(zoneUrl) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }

    @Test
    public void testLocalSamlIdpLoginInTestZone1Works() throws Exception {
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        String testZone1Url = baseUrl.replace("localhost", zoneId + ".localhost");
        String zoneAdminClientId = new RandomValueStringGenerator().generate() + "-" + zoneId + "-admin";
        BaseClientDetails clientDetails = new BaseClientDetails(zoneAdminClientId, null, "uaa.none", "client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", testZone1Url);
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(testZone1Url, new String[0], zoneAdminClientId, "secret")
            );
        String zoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        IntegrationTestUtils.createUser(zoneAdminClient, testZone1Url, zoneUserEmail, "Dana", "Scully", zoneUserEmail, true);

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

        List<WebElement> elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());

        WebElement element = elements.get(0);
        assertNotNull(element);
        element.click();
        IntegrationTestUtils.takeScreenShot(webDriver);
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + zoneId + "]!')]"));
        IntegrationTestUtils.takeScreenShot(webDriver);
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(zoneUserEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");

        //disable the provider
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        //enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    //@Test
    public void testLoginPageShowsIDPsForAuthcodeClient() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider("simplesamlphp");
        IdentityProvider<SamlIdentityProviderDefinition> provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(
            provider.getConfig().getIdpEntityAlias(),
            provider2.getConfig().getIdpEntityAlias()
        );

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']"));
        webDriver.findElement(By.xpath("//a[text()='" + provider2.getConfig().getLinkText() + "']"));
    }

    //@Test
    public void testLoginSamlOnlyProviderNoUsernamePassword() throws Exception {
        IdentityProvider provider = createIdentityProvider("simplesamlphp");
        IdentityProvider provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(provider.getOriginKey(), provider2.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.none", "http://localhost:8080/uaa/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        testClient.createClient(adminAccessToken, clientDetails);
        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fuaa%3Alogin&response_type=code&state=8tp0tR");
        try {
            webDriver.findElement(By.name("username"));
            fail("Element username should not be present");
        } catch (NoSuchElementException x) {}
        try {
            webDriver.findElement(By.name("password"));
            fail("Element username should not be present");
        } catch (NoSuchElementException x) {}
        webDriver.get(baseUrl + "/logout.do");
    }

    //@Test
    public void testSamlLoginClientIDPAuthorizationAutomaticRedirect() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider("simplesamlphp");
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());
        List<String> idps = Arrays.asList(provider.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.none", baseUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(baseUrl) + "&response_type=code&state=8tp0tR");
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        webDriver.get(baseUrl + "/logout.do");
    }

    //@Test
    public void testLoginClientIDPAuthorizationAlreadyLoggedIn() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        List<String> idps = Arrays.asList("okta-local"); //not authorized for the current IDP
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");

        assertThat(webDriver.findElement(By.cssSelector("p")).getText(), Matchers.containsString("The application is not authorized for your account."));
        webDriver.get(baseUrl + "/logout.do");
    }


    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(), new byte[] {127,0,0,1}) &&
                Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(), new byte[] {127,0,0,1}) &&
            Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(), new byte[] {127,0,0,1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public SamlIdentityProviderDefinition createTestZone2IDP(String alias) {
        return createLocalSamlIDP(alias, "testzone2");
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createLocalSamlIDP(alias, "testzone1");
    }

}
