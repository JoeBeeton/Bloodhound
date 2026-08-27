package org.freedonia.bloodhound.server.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Documents the read-only external data API at /swagger-ui.html - springdoc
 * generates the actual endpoint/schema listing by scanning controllers, this
 * just supplies the top-level info and the apiKey security scheme so "Try it
 * out" in the UI (and any generated client) knows to send a bearer token
 * minted by {@code POST /api/v1/api-keys}.
 *
 * <p>This describes every controller springdoc finds, including ones an API
 * key can't actually call (write endpoints, admin routes) - the spec is a
 * map of the whole REST API, not a promise of what a given credential can
 * reach; SecurityConfig's allowlist is the actual enforcement point.
 */
@Configuration
public class OpenApiConfig {

    private static final String API_KEY_SCHEME = "ApiKeyAuth";

    @Bean
    public OpenAPI bloodhoundOpenApi() {
        return new OpenAPI()
                // Without an explicit server list, springdoc derives one from the Host header of
                // whatever request fetched /v3/api-docs - since webui's proxy (see
                // webui.proxy.ApiProxyController) fetches that server-side from central-server's
                // internal Docker hostname, every real user's Swagger UI "Try it out" silently
                // pointed at http://central-server:8080, unreachable from a browser. A single
                // relative "/" server makes every generated request resolve against whatever
                // origin actually served the page - always webui's proxy in every real deployment.
                .servers(List.of(new Server().url("/")))
                .info(new Info()
                        .title("Bloodhound API")
                        .version("v1")
                        .description(
                                "Read-only external access to your organization's attack-surface data - "
                                        + "targets, findings, subdomains, scores, and scan history. Authenticate "
                                        + "with an API key generated via POST /api/v1/api-keys (requires an "
                                        + "existing login session - see the main app's Settings page), sent as "
                                        + "'Authorization: Bearer <key>'. Keys are read-only: every endpoint "
                                        + "reachable with one is a GET."))
                .addSecurityItem(new SecurityRequirement().addList(API_KEY_SCHEME))
                .components(new Components()
                        .addSecuritySchemes(
                                API_KEY_SCHEME,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("bhk_...")
                                        .description(
                                                "An API key minted by POST /api/v1/api-keys, sent as a bearer token.")));
    }
}
