package org.freedonia.bloodhound.server.mcp;

import static org.springframework.security.config.Customizer.withDefaults;

import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;
import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

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
     *
     * <p>Deliberately does NOT call {@code .authenticationManager(...)} explicitly on this chain:
     * doing so replaces its shared AuthenticationManagerBuilder with a fixed manager, which stops
     * McpAuthorizationServerConfigurer from registering its own OAuth2 authorization-request
     * providers into it (confirmed live: ProviderNotFoundException for
     * OAuth2AuthorizationCodeRequestAuthenticationToken - the AS filter never got a provider that
     * could authenticate its own authorization requests). Leaving it unset lets Spring Security
     * build this chain's manager the normal way - SecurityConfig's global authenticationManager
     * bean as parent (so formLogin still authenticates local users) with the AS configurer's own
     * providers layered on top.
     */
    @Bean
    @Order(-10)
    public SecurityFilterChain mcpAuthorizationServerFilterChain(
            HttpSecurity http, LoginAttemptLimiter loginAttemptLimiter) throws Exception {
        http.securityMatcher("/oauth2/**", "/.well-known/**", "/login", "/login/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // Dynamic Client Registration (RFC 7591) - lets an MCP client (e.g. claude.ai's
                // connector UI) self-register a client_id/secret without an admin pre-creating one.
                // Reachable with zero authentication by design (see DcrRateLimiter's javadoc for
                // why that still needs its own bound, confirmed live as an unauthenticated,
                // unbounded storage-growth DoS otherwise) - see mcpDcrRateLimitFilterRegistration
                // below for where that bound is actually enforced; it can't be wired in here via
                // the usual addFilterBefore(..., OAuth2ClientRegistrationEndpointFilter.class),
                // since that filter class has no registered order yet at the point this chain is
                // being built (confirmed live: IllegalArgumentException, "does not have a
                // registered order" - McpAuthorizationServerConfigurer only registers it during
                // its own later configure() phase).
                .with(
                        McpAuthorizationServerConfigurer.mcpAuthorizationServer().dynamicClientRegistration(true),
                        withDefaults())
                // A security review found this formLogin() authenticates straight against the
                // shared authenticationManager bean, bypassing AuthenticationService#login
                // entirely - meaning LoginAttemptLimiter's brute-force lockout (10 failures/15min,
                // see its own javadoc) never applied to this second password-entry point at all.
                // McpLoginRateLimitFilter below does the pre-check (rejecting an already
                // locked-out email before a single BCrypt comparison runs); these handlers record
                // each attempt against the same limiter, the same checkAllowed+recordFailure/
                // recordSuccess split AuthenticationService#login uses. Explicit handler instances
                // (not withDefaults()) so the record* calls can be added while keeping the exact
                // same redirect behavior formLogin's own defaults would otherwise provide.
                .formLogin(form -> form.successHandler((request, response, authentication) -> {
                            loginAttemptLimiter.recordSuccess(authentication.getName());
                            new SavedRequestAwareAuthenticationSuccessHandler()
                                    .onAuthenticationSuccess(request, response, authentication);
                        })
                        .failureHandler((request, response, exception) -> {
                            loginAttemptLimiter.recordFailure(request.getParameter("username"));
                            new SimpleUrlAuthenticationFailureHandler("/login?error")
                                    .onAuthenticationFailure(request, response, exception);
                        }))
                .addFilterBefore(
                        new McpLoginRateLimitFilter(loginAttemptLimiter), UsernamePasswordAuthenticationFilter.class);
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
            HttpSecurity http,
            JwtDecoder mcpJwtDecoder,
            @Value("${bloodhound.mcp.issuer-uri}") String issuerUri,
            UserRepository userRepository,
            OrganizationRepository organizationRepository)
            throws Exception {
        http.securityMatcher("/mcp/**")
                // hasAuthority, not just authenticated(): a security review noted this chain never
                // actually checked the token's scope - any validly signed, right-audience JWT from
                // this AS would pass regardless of what it was granted for. Harmless today (mcp.read
                // is the only scope that exists), but nothing would stop a future narrower scope
                // (e.g. a write-capable one) from also working here by accident. Spring's default
                // JwtGrantedAuthoritiesConverter maps the token's scope claim to SCOPE_<value>
                // authorities - confirmed live that a token without SCOPE_mcp.read is rejected here.
                .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_mcp.read"))
                .with(McpServerOAuth2Configurer.mcpServerOAuth2(), (mcpAuthorization) -> {
                    // authorizationServer(issuerUri) is required (non-null-checked internally) for the
                    // issuer/audience metadata, but jwtDecoder(...) - set after it - takes priority for
                    // actually building the decoder, skipping the OIDC-discovery HTTP fetch the issuer-only
                    // form would otherwise perform against itself during startup (see the class javadoc).
                    mcpAuthorization.authorizationServer(issuerUri);
                    mcpAuthorization.jwtDecoder(mcpJwtDecoder);
                    mcpAuthorization.validateAudienceClaim(true);
                })
                .addFilterAfter(
                        new McpEnabledGuardFilter(userRepository, organizationRepository),
                        BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    /**
     * A plain servlet-container filter (Spring Boot's own registration mechanism, not Spring
     * Security's addFilterBefore/After), matched to POST /oauth2/register and given the highest
     * possible precedence so it runs before Spring Security's whole FilterChainProxy even engages
     * - the one placement that sidesteps the ordinal-registration problem documented on
     * mcpAuthorizationServerFilterChain above entirely, since it doesn't need Spring Security to
     * know anything about where any other filter sits.
     */
    @Bean
    public FilterRegistrationBean<McpDcrRateLimitFilter> mcpDcrRateLimitFilterRegistration(
            DcrRateLimiter dcrRateLimiter) {
        FilterRegistrationBean<McpDcrRateLimitFilter> registration =
                new FilterRegistrationBean<>(new McpDcrRateLimitFilter(dcrRateLimiter));
        registration.addUrlPatterns("/oauth2/register");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
