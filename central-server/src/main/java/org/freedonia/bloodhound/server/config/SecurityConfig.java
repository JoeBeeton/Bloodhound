package org.freedonia.bloodhound.server.config;

import jakarta.servlet.http.HttpServletResponse;
import org.freedonia.bloodhound.server.apikey.ApiKeyAuthFilter;
import org.freedonia.bloodhound.server.apikey.ApiKeyRateLimiter;
import org.freedonia.bloodhound.server.apikey.ApiKeyRepository;
import org.freedonia.bloodhound.server.auth.CustomUserDetailsService;
import org.freedonia.bloodhound.server.auth.JwtAuthenticationFilter;
import org.freedonia.bloodhound.server.auth.JwtService;
import org.freedonia.bloodhound.server.auth.WorkerApiKeyAuthFilter;
import org.freedonia.bloodhound.server.auth.WorkerCredentialRepository;
import org.freedonia.bloodhound.server.auth.sso.SamlAuthenticationSuccessHandler;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.scim.ScimTokenAuthFilter;
import org.freedonia.bloodhound.server.scim.ScimTokenRateLimiter;
import org.freedonia.bloodhound.server.scim.ScimTokenRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Stateless JWT bearer auth. Local username/password login issues the JWT
 * (see auth.AuthController); everything else just validates the bearer token
 * on each request. Public: health checks and /api/v1/auth/**. /api/v1/jobs/**
 * (the worker-facing job queue) requires the separate X-Worker-Api-Key
 * mechanism and ROLE_WORKER specifically; every other route requires a user
 * JWT with one of ADMIN/ANALYST/VIEWER - so worker keys and user JWTs can
 * never satisfy each other's routes. Self-service read-only API keys (see
 * apikey.ApiKeyController/ApiKeyAuthFilter) authenticate the same "Authorization:
 * Bearer" header as a JWT but grant only ROLE_API_KEY, which this chain only
 * ever accepts for GET requests against an explicit data-retrieval allowlist.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Cost 12, not BCryptPasswordEncoder's own default of 10 - current OWASP guidance for new
     * deployments. Bumping this is safe for already-stored hashes: BCrypt encodes its own cost
     * factor in the hash string itself, so verifying an existing cost-10 hash still works
     * correctly against a cost-12 encoder - only newly-created/changed passwords get the higher
     * cost, nothing needs a migration.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        // Spring Security 7 removed the no-arg constructor + setUserDetailsService() -
        // UserDetailsService is now a required constructor argument.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    /**
     * SAML's redirect-to-IdP-and-back flow needs to correlate the outbound
     * AuthnRequest with the inbound assertion across two separate browser
     * round trips - Spring Security's SAML2 login support does this via the
     * HTTP session, which the main API chain below deliberately disables
     * (SessionCreationPolicy.STATELESS, a pure JWT-bearer API). Rather than
     * relax statelessness for the whole app, this is a second filter chain
     * scoped ONLY to the SAML endpoints (matched first via @Order(1), before
     * the catch-all chain), with ordinary session support - once the flow
     * completes, SamlAuthenticationSuccessHandler redirects out of this
     * chain entirely and back into the app's normal stateless JWT world via
     * the one-time handoff code. The main chain is completely unmodified by
     * this - local username/password auth has zero session dependency, same
     * as before.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain samlFilterChain(
            HttpSecurity http,
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
            SamlAuthenticationSuccessHandler samlAuthenticationSuccessHandler)
            throws Exception {
        http.securityMatcher("/saml2/**", "/login/saml2/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable())
                .saml2Login(saml2 -> saml2.relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                        .successHandler(samlAuthenticationSuccessHandler));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            JwtService jwtService,
            UserRepository userRepository,
            WorkerCredentialRepository workerCredentialRepository,
            ScimTokenRepository scimTokenRepository,
            ScimTokenRateLimiter scimTokenRateLimiter,
            ApiKeyRepository apiKeyRepository,
            ApiKeyRateLimiter apiKeyRateLimiter)
            throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.requestMatchers(
                                "/healthz",
                                "/actuator/health",
                                "/actuator/health/**",
                                "/api/v1/auth/**",
                                "/api/v1/public/**",
                                "/error",
                                // The OpenAPI spec + Swagger UI for the read-only external API
                                // (see apikey.ApiKeyController) - documentation only, no data, same
                                // as any public API reference (Stripe/GitHub docs are public too).
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**")
                        .permitAll()
                        .requestMatchers("/api/v1/jobs/**")
                        .hasRole("WORKER")
                        // Distinct bearer-token mechanism from JWT (see ScimTokenAuthFilter) and its own
                        // role, so a SCIM token can never satisfy a user route and a user JWT can never
                        // satisfy /scim/v2/** - same isolation principle as ROLE_WORKER above.
                        .requestMatchers("/scim/v2/**")
                        .hasRole("SCIM")
                        // ROLE_API_KEY (see apikey.ApiKeyAuthFilter) is deliberately never added to the
                        // plain anyRequest() rule below - this GET-only allowlist of data-retrieval
                        // routes is the ONLY way an API key can ever satisfy a request, enforced at the
                        // filter-chain level so it holds regardless of any individual controller's own
                        // logic. Never add a non-GET matcher here.
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/targets/**",
                                "/api/v1/dashboard",
                                "/api/v1/compare",
                                "/api/v1/findings",
                                // Exact-match above, not a wildcard, so the org-wide CSV export
                                // needs its own explicit entry - a live spot-check found it fell
                                // through to the plain anyRequest() rule below (JWT session
                                // roles only), unlike its sibling JSON endpoint just above and the
                                // per-target export (covered by /api/v1/targets/** already).
                                // Not a security gap (fails closed, not open) but a real
                                // inconsistency: an API-key caller could list findings and export
                                // one target's, just not export across the whole org.
                                "/api/v1/findings/export",
                                "/api/v1/runs/**",
                                "/api/v1/rules-catalog",
                                "/api/v1/scans/**")
                        .hasAnyRole("ADMIN", "ANALYST", "VIEWER", "API_KEY")
                        .anyRequest()
                        .hasAnyRole("ADMIN", "ANALYST", "VIEWER"))
                // Without this, Spring Security's default entry point returns 403 for
                // missing/invalid bearer tokens instead of 401.
                .exceptionHandling(eh -> eh.authenticationEntryPoint((request, response, authException) ->
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED)))
                // A ResponseStatusException (e.g. 404/409 from a controller) or a denied
                // AccessDeniedHandler both work via response.sendError(), which Tomcat
                // turns into an internal forward to /error. JwtAuthenticationFilter and
                // WorkerApiKeyAuthFilter are OncePerRequestFilters, which by default don't
                // re-run on that forward - so without this permitAll, the forward reaches
                // AuthorizationFilter with an empty/anonymous SecurityContext, which then
                // denies it and routes to authenticationEntryPoint above, silently
                // clobbering the original status with 401. Discovered via Milestone 2's
                // 403/404 checks (Milestone 1 never exercised a non-401 error path).
                // Constructed directly (not a @Component) so Spring Boot's automatic
                // servlet-filter registration doesn't also run them outside this chain.
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtService, userRepository), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        new WorkerApiKeyAuthFilter(workerCredentialRepository),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        new ScimTokenAuthFilter(scimTokenRepository, scimTokenRateLimiter),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        new ApiKeyAuthFilter(apiKeyRepository, apiKeyRateLimiter),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
