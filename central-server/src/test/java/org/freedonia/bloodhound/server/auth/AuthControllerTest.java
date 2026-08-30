package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.auth.dto.LoginRequest;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final LoginAttemptLimiter loginAttemptLimiter = mock(LoginAttemptLimiter.class);
    private final AuthController controller = new AuthController(authenticationService, loginAttemptLimiter);

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
}
