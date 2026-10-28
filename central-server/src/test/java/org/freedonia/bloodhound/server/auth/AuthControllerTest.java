package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.auth.dto.ForgotPasswordRequest;
import org.freedonia.bloodhound.server.auth.dto.LoginRequest;
import org.freedonia.bloodhound.server.auth.dto.ResetPasswordRequest;
import org.freedonia.bloodhound.server.notification.EmailSender;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.freedonia.bloodhound.server.security.WeakPasswordChecker;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final LoginAttemptLimiter loginAttemptLimiter = mock(LoginAttemptLimiter.class);
    private final ForgotPasswordRateLimiter forgotPasswordRateLimiter = mock(ForgotPasswordRateLimiter.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordResetTokenRepository passwordResetTokenRepository = mock(PasswordResetTokenRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final WeakPasswordChecker weakPasswordChecker = mock(WeakPasswordChecker.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final EmailSender emailSender = mock(EmailSender.class);
    private final AuthController controller = new AuthController(
            authenticationService,
            loginAttemptLimiter,
            forgotPasswordRateLimiter,
            userRepository,
            passwordResetTokenRepository,
            passwordEncoder,
            refreshTokenRepository,
            weakPasswordChecker,
            auditLogRepository,
            emailSender,
            "http://localhost:8090");

    private User localUser(UUID id) {
        return new User(
                id, UUID.randomUUID(), "u@example.com", "Name", "hash", "LOCAL", "VIEWER", "ACTIVE", Instant.now(),
                true, null);
    }

    @Test
    void login_success_returns200WithTokens() {
        User user = new User(
                UUID.randomUUID(), UUID.randomUUID(), "u@example.com", "Name", "hash", "LOCAL", "VIEWER", "ACTIVE",
                Instant.now(), true, null);
        AuthResult result = new AuthResult("access-jwt", 900L, "raw-refresh", UUID.randomUUID(), UserSummary.from(user));
        when(authenticationService.login("u@example.com", "correct-pw")).thenReturn(result);

        ResponseEntity<AuthResponse> response = controller.login(new LoginRequest("u@example.com", "correct-pw"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().accessToken()).isEqualTo("access-jwt");
    }

    @Test
    void login_invalidCredentials_401() {
        when(authenticationService.login("u@example.com", "wrong-pw")).thenThrow(new InvalidCredentialsException());

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> controller.login(new LoginRequest("u@example.com", "wrong-pw")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(401));
    }

    @Test
    void login_rateLimited_429WithRetryAfterHeader_notAGenericError() {
        // The actual point of this test: a product review found the frontend previously had no
        // way to distinguish "you're rate-limited" from any other failure, since both collapsed
        // into the same generic error - a real Retry-After header (not just a status code) is
        // what lets the UI show "try again in N minutes" instead of an unhelpful "try again".
        when(authenticationService.login("u@example.com", "wrong-pw")).thenThrow(new LoginRateLimitedException());
        when(loginAttemptLimiter.remainingLockoutSeconds("u@example.com")).thenReturn(645L);

        ResponseEntity<AuthResponse> response = controller.login(new LoginRequest("u@example.com", "wrong-pw"));

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("645");
    }

    @Test
    void forgotPassword_matchingAccount_createsTokenAndEmails() {
        User user = localUser(UUID.randomUUID());
        when(userRepository.findLocalActiveByEmail("u@example.com")).thenReturn(List.of(user));
        when(passwordResetTokenRepository.create(user.id())).thenReturn("tok123");

        ResponseEntity<Void> response =
                controller.forgotPassword(new ForgotPasswordRequest("u@example.com"), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(202);
        verify(emailSender).send(eq("u@example.com"), anyString(), org.mockito.ArgumentMatchers.contains("tok123"));
        verify(forgotPasswordRateLimiter).recordAttempt(any(), eq("u@example.com"));
    }

    @Test
    void forgotPassword_noMatchingAccount_stillReturns202_neverEmails() {
        // The actual point of this test: the response must be identical whether or not the email
        // matched an account - see the endpoint's own javadoc for why (email enumeration).
        when(userRepository.findLocalActiveByEmail("nobody@example.com")).thenReturn(List.of());

        ResponseEntity<Void> response = controller.forgotPassword(
                new ForgotPasswordRequest("nobody@example.com"), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(202);
        verify(emailSender, never()).send(any(), any(), any());
    }

    @Test
    void forgotPassword_rateLimited_429WithRetryAfterHeader() {
        doThrowRateLimited();
        when(forgotPasswordRateLimiter.remainingLockoutSeconds(anyString(), eq("u@example.com"))).thenReturn(300L);

        ResponseEntity<Void> response =
                controller.forgotPassword(new ForgotPasswordRequest("u@example.com"), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("300");
        verify(userRepository, never()).findLocalActiveByEmail(any());
    }

    private void doThrowRateLimited() {
        org.mockito.Mockito.doThrow(new ForgotPasswordRateLimiter.ForgotPasswordRateLimitedException())
                .when(forgotPasswordRateLimiter)
                .checkAllowed(anyString(), eq("u@example.com"));
    }

    @Test
    void resetPassword_invalidOrExpiredToken_400WithMessage_notABareStatusException() {
        when(passwordResetTokenRepository.consume("bad-token")).thenReturn(Optional.empty());

        ResponseEntity<?> response = controller.resetPassword(new ResetPasswordRequest("bad-token", "new-password-123"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).isInstanceOf(AuthController.ErrorMessageResponse.class);
    }

    @Test
    void resetPassword_weakPassword_400WithMessage() {
        User user = localUser(UUID.randomUUID());
        when(passwordResetTokenRepository.consume("tok")).thenReturn(Optional.of(user.id()));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(weakPasswordChecker.isWeak("password1", user.email())).thenReturn(true);

        ResponseEntity<?> response = controller.resetPassword(new ResetPasswordRequest("tok", "password1"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verify(userRepository, never()).updatePasswordHash(any(), any());
    }

    @Test
    void resetPassword_success_updatesHashAndRevokesSessions() {
        User user = localUser(UUID.randomUUID());
        when(passwordResetTokenRepository.consume("tok")).thenReturn(Optional.of(user.id()));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(weakPasswordChecker.isWeak("a-genuinely-strong-password", user.email())).thenReturn(false);
        when(passwordEncoder.encode("a-genuinely-strong-password")).thenReturn("new-hash");

        ResponseEntity<?> response = controller.resetPassword(new ResetPasswordRequest("tok", "a-genuinely-strong-password"));

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(userRepository).updatePasswordHash(user.id(), "new-hash");
        verify(refreshTokenRepository).revokeAllForUser(user.id());
    }
}
