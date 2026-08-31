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
 * User#mcpEnabled), and that the user is still ACTIVE, on every /mcp/** request - checked live
 * against the database rather than trusted from the token's own org_id/user_id claims (see
 * McpTokenCustomizer) - a toggle flipped by an admin takes effect on a client's very next tool
 * call, not just after its current token expires. Runs after the OAuth2 resource-server filter
 * (added via addFilterAfter in McpSecurityConfig) so the validated Jwt is already the
 * Authentication principal.
 *
 * <p>The status check specifically closes a real gap: Spring's refresh_token grant
 * (McpSecurityConfig's authorization-server chain, {@code /oauth2/token}) re-derives its
 * principal from the *stored* OAuth2Authorization row - the User snapshotted at the original
 * authorization_code exchange - rather than calling CustomUserDetailsService#loadUserByUsername
 * again, so it never re-checks live status the way a fresh login does (see
 * AuthenticatedUserPrincipal#isEnabled, which does gate a *new* authorization). Confirmed live: an
 * ACTIVE user connects an MCP client, is later disabled (offboarded, compromise response, etc.),
 * and - before this fix - their already-issued refresh token kept minting new, working access
 * tokens indefinitely; their web password stopped working, but their AI agent didn't. mcpEnabled
 * alone doesn't help here either, since disabling a user's account doesn't also flip that
 * separate, independent flag. This filter is the actual data-access boundary (every real tool
 * call passes through it), so gating here closes the access even though the underlying refresh
 * token itself is untouched - see mcp.McpConnectionsController for revoking that token directly.
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

        // user_id/org_id are only added by McpTokenCustomizer for a real human-authenticated
        // token (an AuthenticatedUserPrincipal) - a token minted some other way (e.g. a
        // client_credentials grant, which this AS's metadata advertises as supported even though
        // no code here issues one deliberately) would have neither claim. A security review found
        // this previously reached UUID.fromString(null), an unhandled NPE surfacing as a bare 500 -
        // fails closed either way (no data reached the caller), but a deliberate 403 is the correct
        // response for "this token isn't valid for MCP access", not an unhandled exception.
        String userIdClaim = jwt.getClaimAsString("user_id");
        String orgIdClaim = jwt.getClaimAsString("org_id");
        if (userIdClaim == null || orgIdClaim == null) {
            respondDisabled(response);
            return;
        }
        UUID userId = UUID.fromString(userIdClaim);
        UUID orgId = UUID.fromString(orgIdClaim);

        Optional<Organization> org = organizationRepository.findById(orgId);
        Optional<User> user = userRepository.findById(userId);
        boolean orgAllows = org.map(Organization::mcpEnabled).orElse(false);
        boolean userAllows = user.map(User::mcpEnabled).orElse(false);
        boolean userActive = user.map(u -> "ACTIVE".equals(u.status())).orElse(false);

        if (!orgAllows || !userAllows || !userActive) {
            respondDisabled(response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void respondDisabled(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter()
                .write("{\"error\":\"mcp_disabled\",\"error_description\":"
                        + "\"The MCP server is disabled for this organization or user.\"}");
    }
}
