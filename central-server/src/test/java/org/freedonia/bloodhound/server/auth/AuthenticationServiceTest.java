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
            authenticationManager, userRepository, refreshTokenRepository, jwtService, loginAttemptLimiter, 30);

    private User user(UUID id, String status) {
        return new User(id, UUID.randomUUID(), "u@example.com", "Name", "hash", "LOCAL", "VIEWER", status, Instant.now());
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
        verify(refreshTokenRepository).insert(eq(result.refreshTokenId()), eq(user.id()), any(), any());
    }

    @Test
    void refresh_unknownOrExpiredToken_throwsInvalidRefreshToken() {
        when(refreshTokenRepository.findActive(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh("some-raw-token")).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void refresh_tokenBelongsToSuspendedUser_rejected_evenThoughTokenItselfIsValid() {
        UUID userId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(UUID.randomUUID(), userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now());
        when(refreshTokenRepository.findActive(any())).thenReturn(Optional.of(token));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user(userId, "SUSPENDED")));

        assertThatThrownBy(() -> service.refresh("raw-token")).isInstanceOf(InvalidRefreshTokenException.class);
        verify(refreshTokenRepository, never()).revoke(any());
    }

    @Test
    void refresh_validToken_rotatesToNewToken_revokesOld_linksReplacement() {
        UUID userId = UUID.randomUUID();
        User user = user(userId, "ACTIVE");
        UUID oldTokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(oldTokenId, userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now());
        when(refreshTokenRepository.findActive(any())).thenReturn(Optional.of(token));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(jwtService.issueAccessToken(any(), any(), any(), any())).thenReturn("new-jwt");
        when(jwtService.accessTokenTtlSeconds()).thenReturn(900L);

        AuthResult result = service.refresh("raw-old-token");

        verify(refreshTokenRepository).revoke(oldTokenId);
        verify(refreshTokenRepository).linkReplacement(oldTokenId, result.refreshTokenId());
        assertThat(result.accessToken()).isEqualTo("new-jwt");
    }

    @Test
    void logout_activeToken_revoked() {
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(tokenId, UUID.randomUUID(), "hash", Instant.now().plusSeconds(3600), null, Instant.now());
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
