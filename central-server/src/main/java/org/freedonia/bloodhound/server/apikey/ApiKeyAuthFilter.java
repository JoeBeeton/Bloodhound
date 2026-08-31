package org.freedonia.bloodhound.server.apikey;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.freedonia.bloodhound.server.apikey.ApiKeyRateLimiter.ApiKeyRateLimitedException;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates a standard "Authorization: Bearer &lt;key&gt;" header against
 * api_keys and, if valid and unexpired/unrevoked, authenticates the request
 * as ROLE_API_KEY.
 *
 * <p>Reads the same header {@code JwtAuthenticationFilter} already tries
 * first in the chain - a raw API key isn't JWT-formatted, so that filter's
 * parse fails and it clears the context and moves on, letting this filter
 * run next and succeed (same fallthrough {@code ScimTokenAuthFilter} relies
 * on). Constructed directly by SecurityConfig (not a @Component), same
 * reasoning as the other auth filters: avoids Spring Boot double-registering
 * it outside the security chain.
 *
 * <p>Deliberately authenticates as a {@link JwtPrincipal} (role "VIEWER") so
 * every existing {@code @AuthenticationPrincipal JwtPrincipal} controller
 * method - and its existing organization-scoping logic - works unchanged for
 * API-key callers with no per-endpoint code changes. The read-only guarantee
 * does not depend on that role string: it comes from the distinct
 * ROLE_API_KEY authority granted below, which SecurityConfig only ever
 * allows to satisfy GET requests against an explicit allowlist of
 * data-retrieval routes - a leaked or misused key can be denied at the
 * filter-chain level even if some future controller adds a write path that
 * forgets to check the principal's role field.
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthFilter.class);

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyRateLimiter apiKeyRateLimiter;

    public ApiKeyAuthFilter(ApiKeyRepository apiKeyRepository, ApiKeyRateLimiter apiKeyRateLimiter) {
        this.apiKeyRepository = apiKeyRepository;
        this.apiKeyRateLimiter = apiKeyRateLimiter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            Optional<ApiKey> found = apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token));
            if (found.isPresent() && found.get().isActive(Instant.now())) {
                ApiKey apiKey = found.get();
                // See ApiKeyRateLimiter's own javadoc for why this exists - checked before
                // authenticating the request, not after, so a key already over its budget is
                // rejected without ever reaching the actual endpoint logic.
                try {
                    apiKeyRateLimiter.checkAllowed(apiKey.id());
                } catch (ApiKeyRateLimitedException e) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setHeader("Retry-After", String.valueOf(e.retryAfterSeconds()));
                    return;
                }
                apiKeyRateLimiter.recordRequest(apiKey.id());
                var principal = new JwtPrincipal(apiKey.createdByUserId(), apiKey.organizationId(), "VIEWER", null);
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_API_KEY"));
                var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                // A security review found this ran unguarded inline: a transient DB failure here
                // (pure bookkeeping, not part of the auth decision itself) would propagate up and
                // fail an otherwise-valid, already-authenticated request. Losing one "last used"
                // timestamp update is harmless; failing a real API call over it isn't.
                try {
                    apiKeyRepository.touchLastUsed(apiKey.id());
                } catch (RuntimeException e) {
                    log.warn("failed to update last-used timestamp for API key {}", apiKey.id(), e);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
