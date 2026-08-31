package org.freedonia.bloodhound.server.mcp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.auth.LoginRateLimitedException;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A security review found the MCP OAuth2 consent flow's {@code formLogin()} page
 * (McpSecurityConfig) is a second, completely separate password-entry point against the same
 * local accounts as {@code /api/v1/auth/login} - Spring's default {@code
 * UsernamePasswordAuthenticationFilter} authenticates directly against the shared
 * authenticationManager bean, never going through {@code AuthenticationService#login}, so
 * LoginAttemptLimiter's lockout was silently bypassed here: unlimited password guesses against
 * any known email via this second door, completely undoing the existing 10-attempts/15-minute
 * protection.
 *
 * <p>Placed before {@code UsernamePasswordAuthenticationFilter} so a locked-out email is rejected
 * before a single BCrypt comparison runs, mirroring the {@code checkAllowed} pre-check {@code
 * AuthenticationService#login} already does for the JWT login path. Deliberately implemented as a
 * filter, not a custom AuthenticationProvider/AuthenticationManager override -
 * McpSecurityConfig's own javadoc on this chain documents that calling {@code
 * .authenticationManager(...)} breaks the OAuth2 authorization-request provider registration; a
 * filter is the one hook available here that can't interfere with that.
 */
final class McpLoginRateLimitFilter extends OncePerRequestFilter {

    private static final RequestMatcher LOGIN_SUBMIT = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login");

    private final LoginAttemptLimiter loginAttemptLimiter;

    McpLoginRateLimitFilter(LoginAttemptLimiter loginAttemptLimiter) {
        this.loginAttemptLimiter = loginAttemptLimiter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (LOGIN_SUBMIT.matches(request)) {
            try {
                loginAttemptLimiter.checkAllowed(request.getParameter("username"));
            } catch (LoginRateLimitedException e) {
                // Same destination Spring's own default AuthenticationFailureHandler for this
                // chain redirects to (see McpSecurityConfig's failureHandler) - the plain default
                // login page's generic error message is the extent of this first version's UX,
                // same "functional, not styled" scope cut as the rest of this chain.
                response.sendRedirect(request.getContextPath() + "/login?error");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
