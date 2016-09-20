package org.cloudfoundry.identity.uaa.logger;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Appender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.spi.Filter;
import org.apache.log4j.spi.LoggingEvent;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;



@Component
public class LogConfigScheduledTasks {
	

	private static final Log LOGGER = LogFactory.getLog(LogConfigScheduledTasks.class);

    private static final String LOG4J_CATEGORY = "log4j.category.";
    private RestTemplate restTemplate = new RestTemplate();
    ClientCredentialsResourceDetails oauth2resource;
    private OAuth2RestTemplate oauth2RestTemplate;
    
    //Only configured for local, must use client with config.read authority, assuming local uaa is also config server's trusted issuer
    private String clientId = "client";
    private String clientSecret = "clientsecret";
    private String configServerUri = "http://localhost:8888/uaa/default";
    private String getTokenUri = "http://localhost:8080/uaa/oauth/token";

    public void init() {
        System.out.println("LOGS BABY!");
    }

    @SuppressWarnings("unchecked")
    @Scheduled(fixedRate = 60000)
    public void reconfigureLogs() {
        getRemoteLogConfigs().stream().forEach(config -> {
            LogManager.getLogger(config.getName()).setLevel(Level.toLevel(config.getLevel()));
            Collections.list((Enumeration<Appender>) LogManager.getLogger(config.getName()).getAllAppenders()).forEach(appender -> {
                if (StringUtils.isNotEmpty(config.getZoneRegex())) {
                    appender.addFilter(new ZoneFilter(Pattern.compile(config.zoneRegex)));
                } else {
                    appender.clearFilters();
                }
            });
        });
    }
    
    HttpHeaders createHeaders( String username, String password){
    	String auth = username + ":" + password;
    	byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(Charset.forName("US-ASCII")));
    	String authHeader = "Basic " + new String( encodedAuth );
    	HttpHeaders res = new HttpHeaders();
    	res.set("Authorization", authHeader);
    	return res;     	
    }
    

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private List<LogConfig> getRemoteLogConfigs() {	
    	URI tokenGetUri = URI.create(getTokenUri);
    	HttpHeaders tokenGetHeaders = createHeaders(clientId, clientSecret);
    	tokenGetHeaders.add("Accept", "application/json");
    	tokenGetHeaders.add("Content-Type", "application/x-www-form-urlencoded");
    	
    	String body = "grant_type=client_credentials&response_type=token";
    	HttpEntity tokenGetEntity = new HttpEntity<String>(body, tokenGetHeaders);
    	ResponseEntity<Map<String, Object>> tokenResponseEntity = restTemplate.exchange(tokenGetUri, HttpMethod.POST,
    			tokenGetEntity, new ParameterizedTypeReference<Map<String, Object>>() {
                });
    	String tokenResult = (String) tokenResponseEntity.getBody().get("access_token");
    	
        List<LogConfig> result = new ArrayList<>();
        URI requestUri = URI.create(configServerUri);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", "application/json");
        headers.add("Authorization", "bearer " + tokenResult);
        HttpEntity requestEntity = new HttpEntity<>(headers);
        ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(requestUri, HttpMethod.GET,
                requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {
                });

    	LOGGER.debug("responseEntity: " + responseEntity.getBody());
        List<Map<String, Object>> propertySources = (List<Map<String, Object>>) responseEntity.getBody().get("propertySources");
        for (Map<String, Object> propertySource : propertySources) {
            String name = (String) propertySource.get("name");
            if (!name.equals("https://github.com/predix/guardians-config-test/uaa/default/application.properties")) {
                continue;
            }
            Map<String, Object> properties = (Map<String, Object>) propertySource.get("source");
            for (Entry<String, Object> entry : properties.entrySet()) {
                if (!entry.getKey().startsWith(LOG4J_CATEGORY)) {
                    continue;
                }
                String logConfigName = entry.getKey().substring(LOG4J_CATEGORY.length());

            	LOGGER.debug("logConfigName: " + logConfigName);
                String logConfigLevel;
                String logConfigZoneRegex;
                String[] parts = ((String) entry.getValue()).split(",");
                if (1 == parts.length) {
                    logConfigLevel = parts[0];
                	LOGGER.debug("logConfigLevel: " + logConfigLevel);
                    logConfigZoneRegex = null;
                } else if (2 == parts.length) {
                    logConfigLevel = parts[0];
                    logConfigZoneRegex = parts[1];
                	LOGGER.debug("logConfigLevel: " + logConfigLevel);
                } else {
                    continue;
                }
                result.add(new LogConfig(logConfigName, logConfigLevel, logConfigZoneRegex));
            }
        }
        return result;
    }

    public static class LogConfig {
        private String name;
        private String level;
        private String zoneRegex;

        public LogConfig(String name, String level, String zoneRegex) {
            this.name = name;
            this.level = level;
            this.zoneRegex = zoneRegex;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getLevel() {
            return level;
        }

        public void setLevel(String level) {
            this.level = level;
        }

        public String getZoneRegex() {
            return zoneRegex;
        }

        public void setZoneRegex(String zoneRegex) {
            this.zoneRegex = zoneRegex;
        }
    }

    public static class ZoneFilter extends Filter {

        private static final String LOG_ZONE_ID = "Zone-Id";
        private final Pattern zoneRegexPattern;

        public ZoneFilter(final Pattern zoneRegexPattern) {
            if (null == zoneRegexPattern) {
                this.zoneRegexPattern = Pattern.compile(".*");
            } else {
                this.zoneRegexPattern = zoneRegexPattern;
            }
        }

        @Override
        public int decide(LoggingEvent event) {
            String zoneId = event.getProperty(LOG_ZONE_ID);
            if (StringUtils.isEmpty(zoneId)) {
                return Filter.ACCEPT;
            }
            Matcher matcher = this.zoneRegexPattern.matcher(zoneId);
            if (matcher.find()) {
                return Filter.ACCEPT;
            } else {
                return Filter.DENY;
            }
        }
    }
}
