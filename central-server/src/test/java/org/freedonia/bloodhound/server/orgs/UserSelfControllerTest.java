package org.freedonia.bloodhound.server.orgs;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.auth.LoginRateLimitedException;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.orgs.dto.ChangePasswordRequest;
import org.freedonia.bloodhound.server.orgs.dto.LogoutOtherSessionsRequest;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.freedonia.bloodhound.server.security.WeakPasswordChecker;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class UserSelfControllerTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final LoginAttemptLimiter loginAttemptLimiter = mock(LoginAttemptLimiter.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    // Real, not mocked - a lightweight, deterministic component with no external dependencies
    // (loads a bundled resource file once), same reasoning HashUtil is used directly rather than
    // mocked elsewhere in this test class.
    private final WeakPasswordChecker weakPasswordChecker = new WeakPasswordChecker();
    private final UserSelfController controller = new UserSelfController(
            userRepository,
            passwordEncoder,
            refreshTokenRepository,
            loginAttemptLimiter,
            auditLogRepository,
            weakPasswordChecker);

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

        ResponseEntity<?> response =
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

        ResponseEntity<?> response =
                controller.changePassword(new ChangePasswordRequest("whatever", "new-pw"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("645");
        // Checked before doing any other work, same ordering AuthenticationService#login uses.
        verify(userRepository, never()).findById(any());
        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }

    @Test
    void changePassword_correctCurrentPassword_recordsAuditEntry_distinctFromAdminReset() {
        // A security review found this self-service change had no audit trail, unlike the
        // admin-triggered equivalent (OrgUserController's own USER_PASSWORD_RESET) - a distinct
        // action name lets an admin reviewing the log tell "the user changed it themselves" apart
        // from "an admin reset it for them".
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);
        when(passwordEncoder.encode("new-pw")).thenReturn("new-hash");

        controller.changePassword(new ChangePasswordRequest("current-pw", "new-pw"), principal);

        verify(auditLogRepository).record(
                principal.organizationId(), userId, principal.email(), "USER_PASSWORD_CHANGED", "USER", userId.toString(),
                "email=" + principal.email());
    }

    @Test
    void changePassword_wrongCurrentPassword_neverRecordsAudit() {
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("wrong-pw", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest("wrong-pw", "new-pw"), principal))
                .isInstanceOf(ResponseStatusException.class);

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void changePassword_commonPassword_rejectedWithAnExplanatoryMessage_neverStoredOrRevokesTokens() {
        // A security review found newPassword was only length-checked - nothing stopped a
        // trivially guessable value like "password1". Checked only after the current-password
        // verification below succeeds - see the controller's own comment for why. Returns a real
        // response body (unlike the wrong-current-password/non-local-account cases, which throw
        // ResponseStatusException) - confirmed live that this app's default error handler never
        // exposes a ResponseStatusException's reason text to the caller, so a generic "rejected"
        // with no explanation would defeat the point of the check.
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);

        ResponseEntity<?> response =
                controller.changePassword(new ChangePasswordRequest("current-pw", "password1"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).isInstanceOf(UserSelfController.WeakPasswordResponse.class);
        assertThat(((UserSelfController.WeakPasswordResponse) response.getBody()).message()).isNotBlank();
        verify(userRepository, never()).updatePasswordHash(any(), any());
        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }

    @Test
    void changePassword_newPasswordEqualsOwnEmail_rejected() {
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);

        ResponseEntity<?> response = controller.changePassword(
                new ChangePasswordRequest("current-pw", principal.email()), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verify(userRepository, never()).updatePasswordHash(any(), any());
    }

    @Test
    void changePassword_newPasswordEqualsEmailLocalPart_rejected() {
        // principal.email() is "u@example.com" - the local part alone ("u") is just as guessable
        // a choice as the full address.
        User existing = user("LOCAL", "old-hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches("current-pw", "old-hash")).thenReturn(true);

        ResponseEntity<?> response = controller.changePassword(new ChangePasswordRequest("current-pw", "u"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verify(userRepository, never()).updatePasswordHash(any(), any());
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

    @Test
    void logoutOtherSessions_recordsAuditEntry() {
        // "Something feels off, log out everywhere else" is exactly the kind of self-remediation
        // an incident review benefits from being able to see happened (and when), not just infer
        // from a sudden drop in active session count.
        controller.logoutOtherSessions(new LogoutOtherSessionsRequest("raw-current-token"), principal);

        verify(auditLogRepository).record(
                principal.organizationId(), userId, principal.email(), "USER_LOGGED_OUT_OTHER_SESSIONS", "USER",
                userId.toString(), "email=" + principal.email());
    }

    private org.freedonia.bloodhound.server.auth.RefreshToken token(Instant sessionStartedAt) {
        return new org.freedonia.bloodhound.server.auth.RefreshToken(
                UUID.randomUUID(), userId, "hash", Instant.now().plusSeconds(3600), null, Instant.now(), sessionStartedAt);
    }

    @Test
    void listSessions_mapsRepositoryRowsToSummaries_neverExposingTheTokenHash() {
        Instant started = Instant.parse("2026-01-01T00:00:00Z");
        when(refreshTokenRepository.listActiveForUser(userId)).thenReturn(List.of(token(started)));

        List<UserSelfController.SessionSummary> result = controller.listSessions(principal);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).sessionStartedAt()).isEqualTo(started);
    }

    @Test
    void revokeSession_ownedSession_revokesAndRecordsAudit() {
        UUID sessionId = UUID.randomUUID();
        when(refreshTokenRepository.revokeOwnedByUser(sessionId, userId)).thenReturn(1);

        ResponseEntity<Void> response = controller.revokeSession(sessionId, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(auditLogRepository).record(
                principal.organizationId(), userId, principal.email(), "USER_SESSION_REVOKED", "USER", userId.toString(),
                "sessionId=" + sessionId);
    }

    @Test
    void revokeSession_notOwnedOrAlreadyGone_notFound_neverRecordsAudit() {
        // The security point of this test: revokeOwnedByUser's own WHERE clause (id AND user_id)
        // is what makes this safe to expose behind a bare path-variable UUID at all - without it,
        // any authenticated user could revoke any other user's session by guessing an id.
        UUID sessionId = UUID.randomUUID();
        when(refreshTokenRepository.revokeOwnedByUser(sessionId, userId)).thenReturn(0);

        assertThatThrownBy(() -> controller.revokeSession(sessionId, principal)).isInstanceOf(ResponseStatusException.class);

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }
}
