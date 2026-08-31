package org.freedonia.bloodhound.server.apikey;

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
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

class ApiKeyAuthFilterTest {

    private final ApiKeyRepository apiKeyRepository = mock(ApiKeyRepository.class);
    private final ApiKeyRateLimiter apiKeyRateLimiter = new ApiKeyRateLimiter();
    private final ApiKeyAuthFilter filter = new ApiKeyAuthFilter(apiKeyRepository, apiKeyRateLimiter);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain filterChain = mock(FilterChain.class);

    private ApiKey activeKey(UUID orgId, UUID userId) {
        return new ApiKey(
                UUID.randomUUID(), orgId, userId, "label", "bhk_abcdef", "hash",
                Instant.now().minus(1, ChronoUnit.DAYS), Instant.now().plus(1, ChronoUnit.DAYS), null, null);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validActiveKey_authenticatesAsRoleApiKeyWithOwningOrgAndUser() throws Exception {
        UUID orgId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        String token = "bhk_realtoken";
        ApiKey key = activeKey(orgId, userId);
        when(apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(key));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_API_KEY");
        JwtPrincipal principal = (JwtPrincipal) auth.getPrincipal();
        assertThat(principal.organizationId()).isEqualTo(orgId);
        assertThat(principal.userId()).isEqualTo(userId);
        verify(apiKeyRepository).touchLastUsed(key.id());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void expiredKey_doesNotAuthenticate() throws Exception {
        String token = "bhk_expiredtoken";
        ApiKey expired = new ApiKey(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "label", "bhk_ab", "hash",
                Instant.now().minus(2, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.MINUTES), null, null);
        when(apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(expired));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(apiKeyRepository, never()).touchLastUsed(any());
    }

    @Test
    void revokedKey_doesNotAuthenticate() throws Exception {
        String token = "bhk_revokedtoken";
        ApiKey revoked = new ApiKey(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "label", "bhk_ab", "hash",
                Instant.now().minus(2, ChronoUnit.DAYS), Instant.now().plus(1, ChronoUnit.DAYS), null, Instant.now());
        when(apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(revoked));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void unknownKey_doesNotAuthenticate() throws Exception {
        when(apiKeyRepository.findByKeyHash(any())).thenReturn(Optional.empty());

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer bhk_notreal");

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
    void keyOverItsRateLimit_returns429_neverAuthenticates_neverReachesTheChain() throws Exception {
        // A security review found this filter had no rate limiting at all - once authenticated, a
        // caller could hit any allowlisted GET/export endpoint at unlimited request rate.
        String token = "bhk_realtoken";
        ApiKey key = activeKey(UUID.randomUUID(), UUID.randomUUID());
        when(apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(key));
        for (int i = 0; i < 120; i++) {
            apiKeyRateLimiter.recordRequest(key.id());
        }

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        org.springframework.mock.web.MockHttpServletResponse realResponse =
                new org.springframework.mock.web.MockHttpServletResponse();

        filter.doFilterInternal(request, realResponse, filterChain);

        assertThat(realResponse.getStatus()).isEqualTo(429);
        assertThat(realResponse.getHeader("Retry-After")).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(apiKeyRepository, never()).touchLastUsed(any());
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void keyUnderItsRateLimit_stillAuthenticatesNormally() throws Exception {
        String token = "bhk_realtoken";
        ApiKey key = activeKey(UUID.randomUUID(), UUID.randomUUID());
        when(apiKeyRepository.findByKeyHash(HashUtil.sha256Hex(token))).thenReturn(Optional.of(key));
        for (int i = 0; i < 119; i++) {
            apiKeyRateLimiter.recordRequest(key.id());
        }

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(request, response);
    }
}
