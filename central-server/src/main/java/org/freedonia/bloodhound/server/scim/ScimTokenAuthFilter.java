package org.freedonia.bloodhound.server.scim;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.freedonia.bloodhound.server.scim.ScimTokenRateLimiter.ScimTokenRateLimitedException;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates a standard "Authorization: Bearer &lt;token&gt;" header against
 * scim_tokens and, if valid, authenticates the request as ROLE_SCIM with a
 * ScimPrincipal (carrying the token's organization_id) as principal.
 *
 * <p>This reads the same header JwtAuthenticationFilter already tries first
 * in the chain - a SCIM token isn't JWT-formatted, so JwtService.parseAndValidate
 * throws JwtException/IllegalArgumentException there and that filter clears
 * the context and moves on (see its own doFilterInternal), letting this
 * filter run next and succeed. Constructed directly by SecurityConfig (not a
 * @Component), same reasoning as JwtAuthenticationFilter/WorkerApiKeyAuthFilter:
 * avoids Spring Boot double-registering it outside the security chain.
 */
public class ScimTokenAuthFilter extends OncePerRequestFilter {

    private final ScimTokenRepository scimTokenRepository;
    private final ScimTokenRateLimiter scimTokenRateLimiter;

    public ScimTokenAuthFilter(ScimTokenRepository scimTokenRepository, ScimTokenRateLimiter scimTokenRateLimiter) {
        this.scimTokenRepository = scimTokenRepository;
        this.scimTokenRateLimiter = scimTokenRateLimiter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            Optional<ScimToken> found = scimTokenRepository.findActiveByTokenHash(HashUtil.sha256Hex(token));
            if (found.isPresent()) {
                ScimToken scimToken = found.get();
                // See ScimTokenRateLimiter's own javadoc for why this exists - checked before
                // authenticating the request, same "reject before it ever reaches endpoint logic"
                // ordering ApiKeyAuthFilter already established for the sibling bearer-token path.
                try {
                    scimTokenRateLimiter.checkAllowed(scimToken.id());
                } catch (ScimTokenRateLimitedException e) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setHeader("Retry-After", String.valueOf(e.retryAfterSeconds()));
                    return;
                }
                scimTokenRateLimiter.recordRequest(scimToken.id());
                var principal = new ScimPrincipal(scimToken.organizationId(), scimToken.label());
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_SCIM"));
                var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
