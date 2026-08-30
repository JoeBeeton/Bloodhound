package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.AuthenticatedUserPrincipal;
import org.freedonia.bloodhound.server.orgs.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

class McpTokenCustomizerTest {

    private final OAuth2TokenCustomizer<JwtEncodingContext> customizer =
            new McpTokenCustomizer().mcpJwtCustomizer();

    private final UUID userId = UUID.randomUUID();
    private final UUID orgId = UUID.randomUUID();

    private User user() {
        return new User(userId, orgId, "u@example.com", "Name", "hash", "LOCAL", "ANALYST", "ACTIVE", Instant.now(), true);
    }

    private JwtEncodingContext contextFor(Authentication principal, OAuth2TokenType tokenType) {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(tokenType);
        when(context.getPrincipal()).thenReturn(principal);
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900));
        when(context.getClaims()).thenReturn(claims);
        return context;
    }

    @Test
    void accessToken_authenticatedUserPrincipal_addsUserOrgRoleClaims() {
        UserDetails principalDetails = new AuthenticatedUserPrincipal(user());
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principalDetails, "n/a", principalDetails.getAuthorities());
        JwtEncodingContext context = contextFor(authentication, OAuth2TokenType.ACCESS_TOKEN);

        customizer.customize(context);

        JwtClaimsSet claims = context.getClaims().build();
        assertThat((String) claims.getClaim("user_id")).isEqualTo(userId.toString());
        assertThat((String) claims.getClaim("org_id")).isEqualTo(orgId.toString());
        assertThat((String) claims.getClaim("role")).isEqualTo("ANALYST");
    }

    @Test
    void nonAccessToken_neverInspectsClaimsOrPrincipal() {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType("refresh_token"));

        customizer.customize(context);

        verify(context, never()).getPrincipal();
        verify(context, never()).getClaims();
    }

    @Test
    void accessToken_nonAuthenticatedUserPrincipal_addsNoCustomClaims() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn("some-client-credentials-principal");
        JwtEncodingContext context = contextFor(authentication, OAuth2TokenType.ACCESS_TOKEN);

        customizer.customize(context);

        JwtClaimsSet claims = context.getClaims().build();
        assertThat((String) claims.getClaim("user_id")).isNull();
        assertThat((String) claims.getClaim("org_id")).isNull();
        assertThat((String) claims.getClaim("role")).isNull();
    }
}
