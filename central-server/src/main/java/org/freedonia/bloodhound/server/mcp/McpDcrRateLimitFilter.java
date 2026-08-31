package org.freedonia.bloodhound.server.mcp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.freedonia.bloodhound.server.mcp.DcrRateLimiter.DcrRateLimitedException;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enforces DcrRateLimiter on POST /oauth2/register (see its own javadoc for why this endpoint is
 * unauthenticated by design and why that still needs a bound). Registered as a plain
 * servlet-container filter with the highest possible precedence (see McpSecurityConfig's
 * mcpDcrRateLimitFilterRegistration), not via HttpSecurity#addFilterBefore like
 * McpLoginRateLimitFilter - Spring Authorization Server's own
 * OAuth2ClientRegistrationEndpointFilter has no registered order in Spring Security's
 * FilterOrderRegistration until McpAuthorizationServerConfigurer's own configure() phase runs,
 * which happens after mcpAuthorizationServerFilterChain's own method body finishes (confirmed
 * live: addFilterBefore referencing that class throws "does not have a registered order" at
 * startup) - running ahead of the entire security filter chain sidesteps needing to know its
 * position at all.
 *
 * <p>Still checks the exact path+method itself (not just relying on the servlet mapping's URL
 * pattern), since a servlet filter mapping alone doesn't distinguish HTTP methods - a GET to the
 * same path (metadata discovery, if ever added) must not be rate-limited by this.
 *
 * <p>request.getRemoteAddr() rather than any X-Forwarded-For-style header: this app has no
 * configured trusted-proxy chain anywhere, and honoring a client-supplied header for rate-limit
 * identity would let an attacker simply set a different one per request to bypass the limiter
 * entirely - the direct TCP peer address is spoofable only by actually routing from a different
 * address, which is the property this limiter needs.
 */
final class McpDcrRateLimitFilter extends OncePerRequestFilter {

    private static final RequestMatcher REGISTER_SUBMIT =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/oauth2/register");

    private final DcrRateLimiter dcrRateLimiter;

    McpDcrRateLimitFilter(DcrRateLimiter dcrRateLimiter) {
        this.dcrRateLimiter = dcrRateLimiter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (REGISTER_SUBMIT.matches(request)) {
            String ip = request.getRemoteAddr();
            try {
                dcrRateLimiter.checkAllowed(ip);
            } catch (DcrRateLimitedException e) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("Retry-After", String.valueOf(e.retryAfterSeconds()));
                response.setContentType("application/json");
                response.getWriter()
                        .write("{\"error\":\"request_denied\",\"error_description\":"
                                + "\"too many client registration attempts, try again later\"}");
                return;
            }
            dcrRateLimiter.recordAttempt(ip);
        }
        filterChain.doFilter(request, response);
    }
}
