package org.freedonia.bloodhound.server.apikey;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.HashUtil;
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

    private final ApiKeyRepository apiKeyRepository;

    public ApiKeyAuthFilter(ApiKeyRepository apiKeyRepository) {
        this.apiKeyRepository = apiKeyRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token)).ifPresent(apiKey -> {
                if (!apiKey.isActive(Instant.now())) {
                    return;
                }
                var principal = new JwtPrincipal(apiKey.createdByUserId(), apiKey.organizationId(), "VIEWER", null);
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_API_KEY"));
                var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                apiKeyRepository.touchLastUsed(apiKey.id());
            });
        }
        filterChain.doFilter(request, response);
    }
}
