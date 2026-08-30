package org.freedonia.bloodhound.server.orgs;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.auth.LoginRateLimitedException;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.orgs.dto.ChangePasswordRequest;
import org.freedonia.bloodhound.server.orgs.dto.LogoutOtherSessionsRequest;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class UserSelfControllerTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final LoginAttemptLimiter loginAttemptLimiter = mock(LoginAttemptLimiter.class);
    private final UserSelfController controller =
            new UserSelfController(userRepository, passwordEncoder, refreshTokenRepository, loginAttemptLimiter);

    private final UUID userId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(userId, UUID.randomUUID(), "VIEWER", "u@example.com");

    private User user(String identitySource, String passwordHash) {
        return new User(
                userId, UUID.randomUUID(), "u@example.com", "Name", passwordHash, identitySource, "VIEWER", "ACTIVE",
                Instant.now(), true, null);
    }

    @Test
    void changePassword_correctCurrentPassword_updatesHash_revokesAllRefreshTokens() {
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);
        when(passwordEncoder.encode("new-pw")).thenReturn("new-hash");

        ResponseEntity<Void> response =
                controller.changePassword(new ChangePasswordRequest("current-pw", "new-pw"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(userRepository).updatePasswordHash(userId, "new-hash");
        // The actual point of this test: a security review found this call was previously
        // missing entirely, leaving every other active session (any device) untouched by a
        // password change - the primary self-remediation action a compromised user takes.
        verify(refreshTokenRepository).revokeAllForUser(userId);
    }

    @Test
    void changePassword_wrongCurrentPassword_forbidden_neverRevokesTokens() {
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("wrong-pw", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest("wrong-pw", "new-pw"), principal))
                .isInstanceOf(ResponseStatusException.class);

        verify(userRepository, never()).updatePasswordHash(any(), any());
        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }

    @Test
    void changePassword_wrongCurrentPassword_recordsFailureAgainstTheLimiter() {
        // A security review found this endpoint - the one other place in the app that verifies a
        // password against its stored hash, besides login - had no brute-force guard at all, so
        // an attacker holding a stolen but still-valid session could try unlimited currentPassword
        // guesses here to recover the account's real password.
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("wrong-pw", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest("wrong-pw", "new-pw"), principal))
                .isInstanceOf(ResponseStatusException.class);

        verify(loginAttemptLimiter).checkAllowed(principal.email());
        verify(loginAttemptLimiter).recordFailure(principal.email());
    }

    @Test
    void changePassword_correctCurrentPassword_recordsSuccessAgainstTheLimiter_clearingAnyPriorFailures() {
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);
        when(passwordEncoder.encode("new-pw")).thenReturn("new-hash");

        controller.changePassword(new ChangePasswordRequest("current-pw", "new-pw"), principal);

        verify(loginAttemptLimiter).recordSuccess(principal.email());
        verify(loginAttemptLimiter, never()).recordFailure(any());
    }

    @Test
    void changePassword_rateLimited_returns429WithRetryAfter_neverTouchesThePasswordHash() {
        org.mockito.Mockito.doThrow(new LoginRateLimitedException())
                .when(loginAttemptLimiter)
                .checkAllowed(principal.email());
        when(loginAttemptLimiter.remainingLockoutSeconds(principal.email())).thenReturn(645L);

        ResponseEntity<Void> response =
                controller.changePassword(new ChangePasswordRequest("whatever", "new-pw"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("645");
        // Checked before doing any other work, same ordering AuthenticationService#login uses.
        verify(userRepository, never()).findById(any());
        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }

    @Test
    void changePassword_nonLocalAccount_badRequest_neverRevokesTokens() {
        User existing = user("SAML", null);
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest("whatever", "new-pw"), principal))
                .isInstanceOf(ResponseStatusException.class);

        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }

    @Test
    void countActiveSessions_returnsCountFromRepository() {
        when(refreshTokenRepository.countActiveForUser(userId)).thenReturn(3);

        UserSelfController.ActiveSessionsCount result = controller.countActiveSessions(principal);

        assertThat(result.count()).isEqualTo(3);
    }

    @Test
    void logoutOtherSessions_revokesAllExceptTheCallersOwnCurrentToken() {
        ResponseEntity<Void> response =
                controller.logoutOtherSessions(new LogoutOtherSessionsRequest("raw-current-token"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(refreshTokenRepository).revokeAllForUserExceptHash(userId, HashUtil.sha256Hex("raw-current-token"));
        // The whole point: this must never be confused with the change-password path's
        // revoke-literally-everything call.
        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }
}
