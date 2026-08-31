package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

class McpEnabledGuardFilterTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final McpEnabledGuardFilter filter = new McpEnabledGuardFilter(userRepository, organizationRepository);

    private final UUID userId = UUID.randomUUID();
    private final UUID orgId = UUID.randomUUID();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private User user(boolean mcpEnabled) {
        return new User(userId, orgId, "u@example.com", "Name", "hash", "LOCAL", "ANALYST", "ACTIVE", Instant.now(), mcpEnabled, null);
    }

    private User userWithStatus(String status) {
        return new User(userId, orgId, "u@example.com", "Name", "hash", "LOCAL", "ANALYST", status, Instant.now(), true, null);
    }

    private Organization org(boolean mcpEnabled) {
        return new Organization(orgId, "Org", "org-slug", Instant.now(), mcpEnabled);
    }

    private Jwt jwtFor(UUID user, UUID org) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("user_id", user.toString())
                .claim("org_id", org.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    private void authenticateAsJwt(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(jwt, null));
    }

    @Test
    void bothOrgAndUserEnabled_allowsThrough() throws Exception {
        authenticateAsJwt(jwtFor(userId, orgId));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user(true)));
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(true)));
        HttpServletRequest request = mock(HttpServletRequest.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void userDisabled_orgEnabled_blocksWithForbidden() throws Exception {
        authenticateAsJwt(jwtFor(userId, orgId));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user(false)));
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(true)));
        HttpServletRequest request = mock(HttpServletRequest.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("mcp_disabled");
    }

    @Test
    void orgDisabled_userEnabled_blocksWithForbidden() throws Exception {
        authenticateAsJwt(jwtFor(userId, orgId));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user(true)));
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(false)));
        HttpServletRequest request = mock(HttpServletRequest.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void userDisabledStatus_orgEnabled_mcpEnabledFlagStillTrue_blocksWithForbidden() throws Exception {
        // The real gap this covers: a refresh_token grant re-derives its principal from the
        // stored authorization snapshot, not a fresh CustomUserDetailsService lookup, so
        // disabling a user's account doesn't stop their already-issued MCP refresh token from
        // minting new access tokens - and mcpEnabled is a separate flag that disabling a user
        // doesn't also flip. This filter is the actual point that must catch it.
        authenticateAsJwt(jwtFor(userId, orgId));
        when(userRepository.findById(userId)).thenReturn(Optional.of(userWithStatus("DISABLED")));
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(true)));
        HttpServletRequest request = mock(HttpServletRequest.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("mcp_disabled");
    }

    @Test
    void noJwtPrincipal_passesThroughUnchecked_leavingItToUpstreamAuthorization() throws Exception {
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken("not-a-jwt", null));
        HttpServletRequest request = mock(HttpServletRequest.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
