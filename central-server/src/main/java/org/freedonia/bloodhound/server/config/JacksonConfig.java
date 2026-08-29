package org.freedonia.bloodhound.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

/**
 * Explicit legacy (Jackson 2, {@code com.fasterxml.jackson.databind}) {@link ObjectMapper} bean.
 *
 * <p>Spring Boot 4's autoconfiguration defaults to Jackson 3 ({@code tools.jackson.databind}) - a
 * genuinely different, unrelated Java type from Spring's dependency-injection point of view - so
 * without this bean, every one of this app's own classes that still inject
 * {@code com.fasterxml.jackson.databind.ObjectMapper} directly (~20 repositories/controllers that
 * manually serialize JSONB columns or request/response bodies) fails to start with "No qualifying
 * bean of type 'com.fasterxml.jackson.databind.ObjectMapper' available" - confirmed live on the
 * Boot 4.1.1 migration.
 *
 * <p>{@link Jackson2ObjectMapperBuilder}, not a bare {@code new ObjectMapper()}: it auto-registers
 * whatever Jackson modules are present on the classpath (JavaTimeModule for {@code Instant}, the
 * parameter-names module, etc.) the same way Boot 3's own auto-configuration used to, so
 * {@code Instant}/{@code UUID}-bearing DTOs across the app keep serializing exactly as before.
 *
 * <p>A full migration of this app's own code to Jackson 3 is a separate, larger follow-up (touches
 * ~20 files across every module) - out of scope for the Boot 4 migration itself, which only needs
 * the app to keep working, not to fully modernize its JSON layer in the same pass.
 */
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return Jackson2ObjectMapperBuilder.json().build();
    }
}
