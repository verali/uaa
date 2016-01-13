package org.cloudfoundry.identity.uaa.acceptance;

import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.test.TestProfileEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.web.client.RestTemplate;

@Configuration
public class DefaultAcceptanceTestConfig {
    
    private ConfigurableEnvironment environment = TestProfileEnvironment.getEnvironment();

    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean 
    String client(){
        return environment.getProperty("oauth.clients.admin.id", String.class, "app");
    }
    
    @Bean 
    String clientSecret(){
        return environment.getProperty("oauth.clients.admin.secret", String.class, "appclientsecret");
    }
    
    @Bean
    public TestClient testClient(RestTemplate restTemplate) {
        
        String baseUrl = environment.getProperty("issuer.uri", String.class, "http://localhost:8080/uaa");
        return new TestClient(restTemplate, baseUrl, baseUrl);
    }

}
