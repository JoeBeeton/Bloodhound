package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * A security review found this filter originally trusted org/role/email straight from the
 * token's own claims for its full ~15-minute life, with no live check against the user record at
 * all - disabling or demoting a user revoked their refresh tokens and API keys, but a currently-
 * held access token kept working, with its stale role, until it naturally expired. These tests
 * cover the fix: only the token's sub (user id) is trusted; org/role/email/status are re-derived
 * from a live lookup on every request.
 */
class JwtAuthenticationFilterTest {

    private static final String SIGNING_KEY = "test-signing-key-at-least-32-bytes-long-for-hs256!!";

    private final JwtService jwtService = new JwtService(SIGNING_KEY, 15);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService, userRepository);

    private final UUID userId = UUID.randomUUID();
    private final UUID orgId = UUID.randomUUID();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private String tokenForUser() {
        // Deliberately stale claims (a different org/role/email than the live user record below)
        // - the whole point of these tests is confirming the filter ignores these in favor of a
        // fresh lookup, not that it echoes them back.
        return jwtService.issueAccessToken(userId, UUID.randomUUID(), "VIEWER", "stale@example.com");
    }

    private User user(String role, String status) {
        return new User(
                userId, orgId, "current@example.com", "Name", "hash", "LOCAL", role, status, Instant.now(), true, null);
    }

    private MockHttpServletRequest requestWithBearer(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }

    @Test
    void activeUser_authenticatesWithLiveOrgRoleEmail_notTheTokensStaleClaims() throws Exception {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user("ADMIN", "ACTIVE")));

        filter.doFilter(requestWithBearer(tokenForUser()), new MockHttpServletResponse(), mock(FilterChain.class));

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        JwtPrincipal principal = (JwtPrincipal) auth.getPrincipal();
        assertThat(principal.userId()).isEqualTo(userId);
        assertThat(principal.organizationId()).isEqualTo(orgId);
        assertThat(principal.role()).isEqualTo("ADMIN");
        assertThat(principal.email()).isEqualTo("current@example.com");
        assertThat(auth.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_ADMIN");
    }

    @Test
    void disabledUser_tokenStillCryptographicallyValid_authenticationRejected() throws Exception {
        // The actual regression this closes: a disabled user's already-issued, unexpired access
        // token used to keep working until it naturally expired.
        when(userRepository.findById(userId)).thenReturn(Optional.of(user("VIEWER", "DISABLED")));

        filter.doFilter(requestWithBearer(tokenForUser()), new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void demotedUser_liveRoleUsed_notTheTokensStaleAdminClaim() throws Exception {
        // The other half of the same fix: a demoted admin's already-issued token used to keep
        // granting admin privileges until it naturally expired too.
        String staleAdminToken = jwtService.issueAccessToken(userId, orgId, "ADMIN", "admin@example.com");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user("VIEWER", "ACTIVE")));

        filter.doFilter(requestWithBearer(staleAdminToken), new MockHttpServletResponse(), mock(FilterChain.class));

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(((JwtPrincipal) auth.getPrincipal()).role()).isEqualTo("VIEWER");
        assertThat(auth.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_VIEWER");
    }

    @Test
    void userDeletedAfterTokenWasIssued_authenticationRejected() throws Exception {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        filter.doFilter(requestWithBearer(tokenForUser()), new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void noAuthorizationHeader_passesThroughUnauthenticated_neverQueriesDb() throws Exception {
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        org.mockito.Mockito.verifyNoInteractions(userRepository);
    }

    @Test
    void malformedToken_clearsContext_neverThrows() throws Exception {
        filter.doFilter(requestWithBearer("not-a-real-jwt"), new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
