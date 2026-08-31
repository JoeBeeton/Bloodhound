package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

class ScimTokenAuthFilterTest {

    private final ScimTokenRepository scimTokenRepository = mock(ScimTokenRepository.class);
    private final ScimTokenRateLimiter scimTokenRateLimiter = new ScimTokenRateLimiter();
    private final ScimTokenAuthFilter filter = new ScimTokenAuthFilter(scimTokenRepository, scimTokenRateLimiter);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain filterChain = mock(FilterChain.class);

    private ScimToken activeToken(UUID orgId) {
        return new ScimToken(
                UUID.randomUUID(), orgId, "label", "hash", Instant.now().minus(1, ChronoUnit.DAYS), null, null);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validActiveToken_authenticatesAsRoleScimWithOwningOrg() throws Exception {
        UUID orgId = UUID.randomUUID();
        String token = "scim_realtoken";
        ScimToken scimToken = activeToken(orgId);
        when(scimTokenRepository.findActiveByTokenHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(scimToken));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_SCIM");
        ScimPrincipal principal = (ScimPrincipal) auth.getPrincipal();
        assertThat(principal.organizationId()).isEqualTo(orgId);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void unknownToken_doesNotAuthenticate() throws Exception {
        when(scimTokenRepository.findActiveByTokenHash(any())).thenReturn(Optional.empty());

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer scim_notreal");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void noAuthorizationHeader_doesNotAuthenticate_stillContinuesChain() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void nonBearerAuthorizationHeader_ignored() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void tokenOverItsRateLimit_returns429_neverAuthenticates_neverReachesTheChain() throws Exception {
        // A security review found this filter had no rate limiting at all - unlike
        // apikey.ApiKeyAuthFilter's own ApiKeyRateLimiter, added earlier this session for the
        // exact same class of endpoint. This gap mattered more, not less: ROLE_SCIM has real
        // write access (user provisioning/deprovisioning), unlike ROLE_API_KEY's GET-only scope.
        String token = "scim_realtoken";
        ScimToken scimToken = activeToken(UUID.randomUUID());
        when(scimTokenRepository.findActiveByTokenHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(scimToken));
        for (int i = 0; i < 120; i++) {
            scimTokenRateLimiter.recordRequest(scimToken.id());
        }

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        org.springframework.mock.web.MockHttpServletResponse realResponse =
                new org.springframework.mock.web.MockHttpServletResponse();

        filter.doFilterInternal(request, realResponse, filterChain);

        assertThat(realResponse.getStatus()).isEqualTo(429);
        assertThat(realResponse.getHeader("Retry-After")).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void tokenUnderItsRateLimit_stillAuthenticatesNormally() throws Exception {
        String token = "scim_realtoken";
        ScimToken scimToken = activeToken(UUID.randomUUID());
        when(scimTokenRepository.findActiveByTokenHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(scimToken));
        for (int i = 0; i < 119; i++) {
            scimTokenRateLimiter.recordRequest(scimToken.id());
        }

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(request, response);
    }
}
