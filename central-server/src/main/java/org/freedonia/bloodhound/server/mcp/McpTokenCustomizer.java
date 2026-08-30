package org.freedonia.bloodhound.server.mcp;

import org.freedonia.bloodhound.server.auth.AuthenticatedUserPrincipal;
import org.freedonia.bloodhound.server.orgs.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Adds the same org/role/user-id shape JwtPrincipal already carries for the regular session JWT
 * (see auth.JwtService) onto every MCP access token, so tool implementations can extract
 * org-scoping the same way controllers do today - see McpEnabledGuardFilter, which reads these
 * same claims back out of the resource-server-validated token.
 */
@Configuration
public class McpTokenCustomizer {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> mcpJwtCustomizer() {
        return context -> {
            if (context.getTokenType() != OAuth2TokenType.ACCESS_TOKEN) {
                return;
            }
            Authentication principal = context.getPrincipal();
            if (!(principal.getPrincipal() instanceof AuthenticatedUserPrincipal authenticatedUser)) {
                return;
            }
            User user = authenticatedUser.user();
            context.getClaims()
                    .claim("user_id", user.id().toString())
                    .claim("org_id", user.organizationId().toString())
                    .claim("role", user.role());
        };
    }
}
