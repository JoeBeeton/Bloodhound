package org.freedonia.bloodhound.server.mcp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enforces the org-wide and per-user MCP kill switches (Organization#mcpEnabled,
 * User#mcpEnabled) on every /mcp/** request, checked live against the database rather than
 * trusted from the token's own org_id/user_id claims (see McpTokenCustomizer) - a toggle flipped
 * by an admin takes effect on a client's very next tool call, not just after its current token
 * expires. Runs after the OAuth2 resource-server filter (added via addFilterAfter in
 * McpSecurityConfig) so the validated Jwt is already the Authentication principal.
 */
public class McpEnabledGuardFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;

    public McpEnabledGuardFilter(UserRepository userRepository, OrganizationRepository organizationRepository) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            // No resolved JWT yet (e.g. the request was already rejected upstream) - nothing for
            // this filter to check, let the chain's own authorization rules handle it.
            filterChain.doFilter(request, response);
            return;
        }

        UUID userId = UUID.fromString(jwt.getClaimAsString("user_id"));
        UUID orgId = UUID.fromString(jwt.getClaimAsString("org_id"));

        Optional<Organization> org = organizationRepository.findById(orgId);
        Optional<User> user = userRepository.findById(userId);
        boolean orgAllows = org.map(Organization::mcpEnabled).orElse(false);
        boolean userAllows = user.map(User::mcpEnabled).orElse(false);

        if (!orgAllows || !userAllows) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter()
                    .write("{\"error\":\"mcp_disabled\",\"error_description\":"
                            + "\"The MCP server is disabled for this organization or user.\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
