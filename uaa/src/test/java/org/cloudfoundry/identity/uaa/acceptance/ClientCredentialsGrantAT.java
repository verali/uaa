package org.cloudfoundry.identity.uaa.acceptance;

import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.HttpClientErrorException;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultAcceptanceTestConfig.class)
public class ClientCredentialsGrantAT {

    @Autowired
    TestClient testClient;
	
    @Qualifier("client")
    @Autowired
    String client;
	
    @Qualifier("clientSecret")
    @Autowired
    String secret;

    @Test
    public void testSuccessfulClientCredentialsFlow() throws Exception {
        Assert.assertNotNull(testClient.getOAuthAccessToken(client, secret, "client_credentials", ""));
    }
    
    @Test(expected= HttpClientErrorException.class)
    public void testNullClientCredentialsFlow() throws Exception {
        testClient.getOAuthAccessToken(client, null, "client_credentials", "");
    }
}
