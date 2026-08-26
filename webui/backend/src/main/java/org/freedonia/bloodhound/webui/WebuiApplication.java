package org.freedonia.bloodhound.webui;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

/**
 * Serves the built React SPA from src/main/resources/static (Spring Boot's
 * default static-resource handling) and proxies auth calls to central-server
 * so the browser only ever talks to this service (see auth.AuthProxyController).
 */
@SpringBootApplication
public class WebuiApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebuiApplication.class, args);
    }

    @Bean
    public RestClient centralServerClient(@Value("${bloodhound.central-server-url}") String baseUrl) {
        return RestClient.builder().baseUrl(baseUrl).build();
    }
}
