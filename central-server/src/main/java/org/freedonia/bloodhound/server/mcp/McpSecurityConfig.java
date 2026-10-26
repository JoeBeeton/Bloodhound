package org.freedonia.bloodhound.server.mcp;

import static org.springframework.security.config.Customizer.withDefaults;

import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;
import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;
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
        // A security review found "/login/**" here shadowed the SAML ACS endpoint
        // ("/login/saml2/sso/{slug}", see DbRelyingPartyRegistrationRepository) - Spring's
        // FilterChainProxy dispatches to the FIRST @Order-matching chain, not the most specific
        // one, and this chain's @Order(-10) runs before SecurityConfig's SAML chain at @Order(1).
        // An inbound SAML assertion POST would have hit this formLogin/CSRF-protected chain
        // instead of saml2Login, never actually validating the assertion - likely a 403 (no CSRF
        // token on the IdP's POST) and SSO silently broken, not merely a theoretical ordering
        // quirk. "/login" (exact) is all this chain's own login page needs; nothing under
        // "/login/**" belongs to it - McpLoginConsentPageController only ever serves "/login"
        // itself, and "?error" is a query string, not a path segment, so it doesn't need a
        // wildcard either.
        http.securityMatcher("/oauth2/**", "/.well-known/**", "/login")
                // /.well-known/oauth-protected-resource (RFC 9728) is served from THIS chain, not
                // mcpResourceServerFilterChain below - FilterChainProxy picks the first @Order-matching
                // chain for a request, and this chain's securityMatcher (".well-known/**") beats the
                // other chain's ("/mcp/**") for that path, so whatever that OTHER chain configures
                // never runs here (confirmed live via security debug logging: this chain's own filter
                // list already includes OAuth2ProtectedResourceMetadataFilter). That filter exists here
                // because McpAuthorizationServerConfigurer.dynamicClientRegistration(true) below makes
                // Spring's own OAuth2AuthorizationServerConfigurer auto-add a default, uncustomized
                // oauth2ResourceServer() to THIS HttpSecurity - with no scopes_supported claim, since
                // nothing told it any scopes exist. Without that claim, an MCP client has no way to
                // learn it should request "mcp.read" at /oauth2/authorize: it asks for no scope, Spring
                // AS offers nothing to approve at consent, and the resulting token - though technically
                // valid - carries no scopes, always then rejected by mcpResourceServerFilterChain's
                // hasAuthority("SCOPE_mcp.read") (confirmed live: exactly this sequence, end to end, see
                // commit history). This explicit call reuses that same auto-added configurer (Spring
                // Security keys oauth2ResourceServer() by type per HttpSecurity, so a second call merges
                // rather than replacing) purely to attach scopes_supported - everything else about it
                // (jwt decoding) is still effectively Spring AS's own default - jwt(withDefaults())
                // is set here too (duplicating what McpAuthorizationServerConfigurer would otherwise
                // add on its own) because configurer init() order depends on registration order, not
                // call-site order in this method: calling oauth2ResourceServer() here with ONLY
                // protectedResourceMetadata() set (confirmed live) let its own init() run and call
                // validateConfiguration() before McpAuthorizationServerConfigurer's init() got a
                // chance to add jwt(withDefaults()) itself - startup crashed with "Jwt and Opaque
                // Token are the only supported formats ... and neither was found". Setting jwt()
                // here too makes this call self-sufficient regardless of that ordering.
                .oauth2ResourceServer(rs -> rs.jwt(withDefaults())
                        .protectedResourceMetadata(
                                metadata -> metadata.protectedResourceMetadataCustomizer(builder -> builder.scope("mcp.read"))))
                // formLogin's own automatic permitAll-for-the-login-page only fires for its
                // auto-generated default page - setting loginPage("/login") below to
                // McpLoginConsentPageController's branded one turned that off (confirmed live: an
                // unauthenticated GET /login started 302-redirecting to itself instead of
                // rendering). Permitting it explicitly here is the documented Spring Security
                // approach for a custom login page and doesn't depend on that automatic behavior.
                .authorizeHttpRequests(auth -> auth.requestMatchers("/login").permitAll().anyRequest().authenticated())
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
                        McpAuthorizationServerConfigurer.mcpAuthorizationServer()
                                .dynamicClientRegistration(true)
                                // Spring's built-in DEFAULT_SCOPE_VALIDATOR hard-rejects (invalid_scope)
                                // ANY non-empty scope in a DCR request, full stop - its RFC 7591 reading
                                // is that the server alone decides scope, so a client shouldn't ask.
                                // That was fine while nothing ever told clients what scope existed, but
                                // once the protectedResourceMetadata customizer above started advertising
                                // scopes_supported=["mcp.read"] (see that comment), a spec-following MCP
                                // client reads it and dutifully echoes "mcp.read" back at registration -
                                // confirmed live: DCR started failing with exactly the default validator's
                                // "Invalid Client Registration: scope"/invalid_scope, the moment a real
                                // client picked up the new metadata. Swapping only the scope half (keeping
                                // Spring's own redirect_uri/jwk_set_uri checks) to allow the one scope this
                                // AS ever issues - still rejecting anything else, same as before - fixes
                                // that without reopening DCR to arbitrary attacker-chosen scope names.
                                .dynamicClientRegistrationValidator(
                                        OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                                                .andThen(OAuth2ClientRegistrationAuthenticationValidator
                                                        .DEFAULT_JWK_SET_URI_VALIDATOR)
                                                .andThen(McpSecurityConfig::validateDcrScope))
                                // Branded replacements for Spring's plain default consent page -
                                // see McpLoginConsentPageController's own javadoc for why this
                                // stopped being a reasonable scope cut once self-registered
                                // clients could actually reach it (ConsentRequiringRegisteredClientRepository).
                                .authorizationServer(authServer -> authServer.authorizationEndpoint(
                                        endpoint -> endpoint.consentPage("/oauth2/consent"))),
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
                // loginPage("/login") points at McpLoginConsentPageController's own branded page -
                // see its javadoc - rather than Spring's auto-generated default.
                .formLogin(form -> form.loginPage("/login")
                        .successHandler((request, response, authentication) -> {
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

    /**
     * Replaces Spring's {@code DEFAULT_SCOPE_VALIDATOR} half of DCR validation - see the
     * {@code dynamicClientRegistrationValidator} call above for why. Accepts an omitted/empty
     * scope (ConsentRequiringRegisteredClientRepository then grants {@code mcp.read} itself, per
     * RFC 7591's "server decides" default) or a request for exactly {@code mcp.read} - this AS's
     * only issuable scope (see mcpResourceServerFilterChain's own comment) - and rejects anything
     * else with the same invalid_scope error Spring's own validator would have used, so DCR still
     * can't be used to register a client under an arbitrary, made-up scope name.
     */
    private static final Set<String> SUPPORTED_DCR_SCOPES = Set.of("mcp.read");

    private static void validateDcrScope(OAuth2ClientRegistrationAuthenticationContext context) {
        OAuth2ClientRegistrationAuthenticationToken authentication =
                (OAuth2ClientRegistrationAuthenticationToken) context.getAuthentication();
        List<String> requestedScopes = authentication.getClientRegistration().getScopes();
        if (requestedScopes != null && !SUPPORTED_DCR_SCOPES.containsAll(requestedScopes)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_SCOPE,
                    "Invalid Client Registration: scope",
                    "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2"));
        }
    }
}
