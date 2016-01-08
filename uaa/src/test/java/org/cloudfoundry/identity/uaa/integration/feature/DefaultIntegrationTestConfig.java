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

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.Proxy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.Environment;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.web.client.RestTemplate;

import com.dumbster.smtp.SimpleSmtpServer;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.concurrent.TimeUnit;

@Configuration
@PropertySource("classpath:integration.test.properties")
public class DefaultIntegrationTestConfig {

    @Bean
    public IntegrationTestRule integrationTestRule(@Value("${integration.test.uaa_url}") String baseUrl, Environment environment) {
        boolean forceIntegrationTests = environment.getProperty("forceIntegrationTests") != null;
        return new IntegrationTestRule(baseUrl, forceIntegrationTests);
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean(destroyMethod = "quit")
    public PhantomJSDriver webDriver() {
        DesiredCapabilities desiredCapabilities = new DesiredCapabilities();
        Proxy proxyObject =  createProxyObject();
        if (proxyObject != null)
            desiredCapabilities.setCapability(CapabilityType.PROXY, proxyObject);
        PhantomJSDriver driver = new PhantomJSDriver(desiredCapabilities);
        driver.manage().timeouts().implicitlyWait(15, TimeUnit.SECONDS);
        driver.manage().timeouts().pageLoadTimeout(20, TimeUnit.SECONDS);
        driver.manage().timeouts().setScriptTimeout(15, TimeUnit.SECONDS);
        driver.manage().window().setSize(new Dimension(1024, 768));
        return driver;
    }
    
    private Proxy createProxyObject()
    {
        String proxyHost = System.getProperty("http.proxyHost");
        System.out.println("Proxy Host Initial Value: " + proxyHost);
        if (StringUtils.isBlank(proxyHost))  return null;
        String proxyPort = System.getProperty("http.proxyPort");
        if (!StringUtils.isBlank(proxyPort))
        {
            proxyHost = proxyHost + ':' + proxyPort;
        }
        String noProxiesHosts = System.getProperty("http.nonProxyHosts");
        Proxy proxy = new Proxy();
        proxy.setHttpProxy(proxyHost);
        if (!StringUtils.isBlank(noProxiesHosts))
        {
            proxy.setNoProxy(noProxiesHosts);
        }
        System.out.println("Proxy Host: " + proxyHost + " No Proxies List: " + noProxiesHosts);
        System.out.println("Created Proxy object: " + proxy);
        return proxy;
    }

    @Bean(destroyMethod = "stop")
    public SimpleSmtpServer simpleSmtpServer(@Value("${smtp.port}") int port) {
        return SimpleSmtpServer.start(port);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public TestClient testClient(RestTemplate restTemplate,
                                 @Value("${integration.test.uaa_url}") String baseUrl,
                                 @Value("${integration.test.uaa_url}") String uaaUrl) {
        return new TestClient(restTemplate, baseUrl, uaaUrl);
    }

    @Bean
    public TestAccounts testAccounts(@Value("${integration.test.uaa_url}") String uaaUrl) {
        //TODO - actually USE the URL?
        return UaaTestAccounts.standard(null);
    }

    public static class HttpClientFactory extends SimpleClientHttpRequestFactory {
        protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
            super.prepareConnection(connection, httpMethod);
            connection.setInstanceFollowRedirects(false);
        }
    }
}
