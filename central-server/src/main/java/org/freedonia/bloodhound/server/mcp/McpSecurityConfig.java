package org.freedonia.bloodhound.server.mcp;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;
import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Two new filter chains for the OAuth2-authenticated MCP server, added on top of the existing
 * JWT/SAML/API-key/worker/SCIM chains in SecurityConfig - deliberately kept in their own class
 * and their own package (mcp), not folded into SecurityConfig itself, since this is a large,
 * separable concern with its own supporting beans (McpAuthorizationServerBeans, McpTokenCustomizer).
 *
 * <p>Ordering: both chains sit before SecurityConfig's @Order(1) SAML chain and @Order(2)
 * catch-all - @Order(-10)/(-9) so they're evaluated first, matching how the SAML chain already
 * carves out its own narrowly-matched exception to the main stateless API chain.
 */
@Configuration
public class McpSecurityConfig {

    /**
     * The authorization-server chain: where a human authorizes an MCP client (e.g. Claude
     * Desktop) to act as them. Needs an authenticated *session* (not this app's usual stateless
     * JWT bearer model) - OAuth2's authorization_code flow is fundamentally a browser-navigated,
     * multi-request flow (redirect to /oauth2/authorize, log in, consent, redirect back with a
     * code), the same reason the existing SAML chain also needs sessions. Reuses the existing
     * authenticationManager bean (the same DaoAuthenticationProvider/CustomUserDetailsService
     * local-login already goes through) via formLogin, rather than building a bespoke bridge to
     * the SPA's own JWT-based login page - Spring's plain default login form for this first
     * version, same "functional, not styled" scope cut as the consent screen below.
     */
    @Bean
    @Order(-10)
    public SecurityFilterChain mcpAuthorizationServerFilterChain(
            HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http.securityMatcher("/oauth2/**", "/.well-known/**", "/login", "/login/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .authenticationManager(authenticationManager)
                .with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), withDefaults())
                .formLogin(withDefaults());
        return http.build();
    }

    /**
     * The resource-server chain: where an already-authorized MCP client actually calls tools.
     * Validates bearer tokens issued by the chain above (issuer-uri points at this same app) -
     * see McpTokenCustomizer for the org/role claims added at issuance, and McpAccessGuard for
     * where the org-wide/per-user MCP kill switches are enforced.
     *
     * <p>Deliberately uses {@code jwtDecoder(...)} with a decoder built directly from the local
     * signing key (see McpAuthorizationServerBeans#mcpJwtDecoder), not {@code authorizationServer
     * (issuerUri)}. The latter builds its decoder via OIDC discovery - an HTTP GET to {@code
     * <issuer>/.well-known/openid-configuration} - performed eagerly while this SecurityFilterChain
     * bean is being constructed, i.e. before Tomcat is accepting connections. Since this app is
     * both the authorization server and the resource server, that self-fetch always fails with
     * connection-refused. Supplying the decoder directly skips the discovery round-trip entirely.
     */
    @Bean
    @Order(-9)
    public SecurityFilterChain mcpResourceServerFilterChain(
            HttpSecurity http, JwtDecoder mcpJwtDecoder, @Value("${bloodhound.mcp.issuer-uri}") String issuerUri)
            throws Exception {
        http.securityMatcher("/mcp/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .with(McpServerOAuth2Configurer.mcpServerOAuth2(), (mcpAuthorization) -> {
                    // authorizationServer(issuerUri) is required (non-null-checked internally) for the
                    // issuer/audience metadata, but jwtDecoder(...) - set after it - takes priority for
                    // actually building the decoder, skipping the OIDC-discovery HTTP fetch the issuer-only
                    // form would otherwise perform against itself during startup (see the class javadoc).
                    mcpAuthorization.authorizationServer(issuerUri);
                    mcpAuthorization.jwtDecoder(mcpJwtDecoder);
                    mcpAuthorization.validateAudienceClaim(true);
                });
        return http.build();
    }
}
