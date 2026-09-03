package org.freedonia.bloodhound.server.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the Authorization: Bearer access token on protected routes and,
 * if valid, populates the SecurityContext with a JwtPrincipal. Constructed
 * directly by SecurityConfig (not a @Component) so Spring Boot's automatic
 * servlet-filter registration doesn't also run it a second time outside the
 * security chain.
 *
 * <p>A security review found this originally trusted org/role/email straight from the token's own
 * claims for its full ~15-minute life, with no live check against the user record at all - MCP's
 * own McpEnabledGuardFilter already did a live check on every /mcp/** request specifically because
 * this path didn't. Disabling or demoting a user (see OrgUserController#update) revoked their
 * refresh tokens and API keys, but a currently-held access token kept working, with its stale
 * role, until it naturally expired - a demoted admin kept admin privileges, and a disabled user
 * kept all access, for up to 15 more minutes. Only the token's {@code sub} (user id) is trusted
 * now; org/role/email/status are re-derived from a live lookup on every request, the same
 * "checked live against the database rather than trusted from the token's own claims" approach
 * McpEnabledGuardFilter already established in this codebase - a toggle flipped by an admin now
 * takes effect on this user's very next request, not just after their session naturally expires.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            try {
                Claims claims = jwtService.parseAndValidate(header.substring(7));
                UUID userId = UUID.fromString(claims.getSubject());
                Optional<User> user = userRepository.findById(userId);
                if (user.isPresent() && "ACTIVE".equals(user.get().status())) {
                    User u = user.get();
                    JwtPrincipal principal = new JwtPrincipal(userId, u.organizationId(), u.role(), u.email());
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + principal.role()));
                    var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    SecurityContextHolder.clearContext();
                }
            } catch (JwtException | IllegalArgumentException e) {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }
}
