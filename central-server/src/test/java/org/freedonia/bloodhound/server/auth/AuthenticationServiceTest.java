package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

class AuthenticationServiceTest {

    private final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final JwtService jwtService = mock(JwtService.class);
    private final LoginAttemptLimiter loginAttemptLimiter = mock(LoginAttemptLimiter.class);
    private final AuthenticationService service = new AuthenticationService(
            authenticationManager, userRepository, refreshTokenRepository, jwtService, loginAttemptLimiter, 30, 90);

    private User user(UUID id, String status) {
        return new User(id, UUID.randomUUID(), "u@example.com", "Name", "hash", "LOCAL", "VIEWER", status, Instant.now(), true, null);
    }

    @Test
    void login_badCredentials_recordsFailure_throwsGenericException_notLeakingWhetherEmailExists() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        assertThatThrownBy(() -> service.login("nobody@example.com", "wrong"))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(loginAttemptLimiter).checkAllowed("nobody@example.com");
        verify(loginAttemptLimiter).recordFailure("nobody@example.com");
        verify(loginAttemptLimiter, never()).recordSuccess(any());
        verify(userRepository, never()).touchLastLogin(any());
    }

    @Test
    void login_rateLimited_neverReachesAuthenticationManager() {
        org.mockito.Mockito.doThrow(new LoginRateLimitedException())
                .when(loginAttemptLimiter)
                .checkAllowed("limited@example.com");

        assertThatThrownBy(() -> service.login("limited@example.com", "pw")).isInstanceOf(LoginRateLimitedException.class);

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void login_success_recordsSuccessNotFailure_touchesLastLogin_issuesTokens() {
        User user = user(UUID.randomUUID(), "ACTIVE");
        Authentication authResult = mockAuthenticationFor(user);
        when(authenticationManager.authenticate(any())).thenReturn(authResult);
        when(jwtService.issueAccessToken(user.id(), user.organizationId(), user.role(), user.email())).thenReturn("jwt-token");
        when(jwtService.accessTokenTtlSeconds()).thenReturn(900L);

        AuthResult result = service.login("u@example.com", "correct-password");

        assertThat(result.accessToken()).isEqualTo("jwt-token");
        assertThat(result.refreshToken()).isNotBlank();
        verify(loginAttemptLimiter).recordSuccess("u@example.com");
        verify(loginAttemptLimiter, never()).recordFailure(any());
        verify(userRepository).touchLastLogin(user.id());
        verify(refreshTokenRepository).insert(eq(result.refreshTokenId()), eq(user.id()), any(), any(), any());
    }

    @Test
    void refresh_unknownToken_throwsInvalidRefreshToken() {
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh("some-raw-token")).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void refresh_expiredToken_rejected_lineageNotTouched() {
        UUID userId = UUID.randomUUID();
        RefreshToken token =
                new RefreshToken(UUID.randomUUID(), userId, "hash", Instant.now().minusSeconds(1), null, Instant.now(), Instant.now());
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> service.refresh("raw-token")).isInstanceOf(InvalidRefreshTokenException.class);
        verify(refreshTokenRepository, never()).revoke(any());
        verify(refreshTokenRepository, never()).revokeLineageFrom(any());
    }

    @Test
    void refresh_alreadyRevokedTokenReplayed_treatedAsTheft_revokesWholeLineage() {
        // Standard OAuth-refresh-rotation hardening: presenting a token that's already been
        // rotated away (revokedAt set) is the reuse/theft signal, not just an ordinary invalid
        // token - the whole lineage forward from it (including whichever token is currently
        // active) must be revoked so neither the attacker nor the legitimate holder can continue.
        UUID userId = UUID.randomUUID();
        UUID revokedTokenId = UUID.randomUUID();
        RefreshToken revokedToken = new RefreshToken(
                revokedTokenId, userId, "hash", Instant.now().plusSeconds(3600), Instant.now().minusSeconds(60), Instant.now(), Instant.now());
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> service.refresh("raw-stolen-token")).isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenRepository).revokeLineageFrom(revokedTokenId);
        // Not the ordinary single-token revoke/rotate path - this is theft handling, not a normal refresh.
        verify(refreshTokenRepository, never()).revoke(any());
        verify(refreshTokenRepository, never()).linkReplacement(any(), any());
        verify(userRepository, never()).findById(any());
    }

    @Test
    void refresh_pastAbsoluteSessionCap_rejected_revokesLineage_evenThoughTokenItselfNotExpiredOrRevoked() {
        // The sliding TTL alone would happily keep renewing this token forever if it's used at
        // least once per window - sessionStartedAt more than absoluteMaxSessionDays (90, per this
        // test's service construction) in the past must be rejected regardless.
        UUID userId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(
                tokenId,
                userId,
                "hash",
                Instant.now().plusSeconds(3600),
                null,
                Instant.now(),
                Instant.now().minus(java.time.Duration.ofDays(91)));
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> service.refresh("raw-token")).isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenRepository).revokeLineageFrom(tokenId);
        verify(userRepository, never()).findById(any());
        verify(refreshTokenRepository, never()).tryRevoke(any());
    }

    @Test
    void refresh_withinAbsoluteSessionCap_succeeds() {
        UUID userId = UUID.randomUUID();
        User user = user(userId, "ACTIVE");
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(
                tokenId,
                userId,
                "hash",
                Instant.now().plusSeconds(3600),
                null,
                Instant.now(),
                Instant.now().minus(java.time.Duration.ofDays(89)));
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));
        when(refreshTokenRepository.tryRevoke(tokenId)).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(jwtService.issueAccessToken(any(), any(), any(), any())).thenReturn("new-jwt");
        when(jwtService.accessTokenTtlSeconds()).thenReturn(900L);

        AuthResult result = service.refresh("raw-token");

        assertThat(result.accessToken()).isEqualTo("new-jwt");
    }

    @Test
    void refresh_tokenBelongsToSuspendedUser_rejected_evenThoughTokenItselfIsValid() {
        UUID userId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(UUID.randomUUID(), userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now(), Instant.now());
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user(userId, "SUSPENDED")));

        assertThatThrownBy(() -> service.refresh("raw-token")).isInstanceOf(InvalidRefreshTokenException.class);
        verify(refreshTokenRepository, never()).revoke(any());
    }

    @Test
    void refresh_validToken_rotatesToNewToken_revokesOld_linksReplacement() {
        UUID userId = UUID.randomUUID();
        User user = user(userId, "ACTIVE");
        UUID oldTokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(oldTokenId, userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now(), Instant.now());
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));
        when(refreshTokenRepository.tryRevoke(oldTokenId)).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(jwtService.issueAccessToken(any(), any(), any(), any())).thenReturn("new-jwt");
        when(jwtService.accessTokenTtlSeconds()).thenReturn(900L);

        AuthResult result = service.refresh("raw-old-token");

        verify(refreshTokenRepository).tryRevoke(oldTokenId);
        verify(refreshTokenRepository).linkReplacement(oldTokenId, result.refreshTokenId());
        verify(refreshTokenRepository, never()).revokeLineageFrom(any());
        assertThat(result.accessToken()).isEqualTo("new-jwt");
    }

    @Test
    void refresh_concurrentRefreshWinsTheRace_thisCallTreatedAsTheft() {
        // The actual race a security review found: two concurrent refresh() calls both read the
        // same still-unrevoked token before either commits its revoke. tryRevoke's atomic
        // UPDATE...WHERE revoked_at IS NULL is what decides a winner - simulated here by having
        // it report "someone else already claimed this" (false), as if another request's
        // statement had executed first.
        UUID userId = UUID.randomUUID();
        User user = user(userId, "ACTIVE");
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(tokenId, userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now(), Instant.now());
        when(refreshTokenRepository.findByHash(any())).thenReturn(Optional.of(token));
        when(refreshTokenRepository.tryRevoke(tokenId)).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.refresh("raw-token")).isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenRepository).revokeLineageFrom(tokenId);
        verify(refreshTokenRepository, never()).linkReplacement(any(), any());
    }

    @Test
    void logout_activeToken_revoked() {
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(tokenId, UUID.randomUUID(), "hash", Instant.now().plusSeconds(3600), null, Instant.now(), Instant.now());
        when(refreshTokenRepository.findActive(any())).thenReturn(Optional.of(token));

        service.logout("raw-token");

        verify(refreshTokenRepository).revoke(tokenId);
    }

    @Test
    void logout_unknownToken_noOp_doesNotThrow() {
        when(refreshTokenRepository.findActive(any())).thenReturn(Optional.empty());

        service.logout("raw-token-that-does-not-exist");

        verify(refreshTokenRepository, never()).revoke(any());
    }

    private Authentication mockAuthenticationFor(User user) {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(new AuthenticatedUserPrincipal(user));
        return authentication;
    }
}
