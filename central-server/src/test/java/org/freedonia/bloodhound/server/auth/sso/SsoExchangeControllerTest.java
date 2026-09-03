package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.AuthResult;
import org.freedonia.bloodhound.server.auth.AuthenticationService;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class SsoExchangeControllerTest {

    private final SsoHandoffCodeRepository handoffCodeRepository = mock(SsoHandoffCodeRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SsoExchangeController controller =
            new SsoExchangeController(handoffCodeRepository, userRepository, authenticationService);

    private final UUID userId = UUID.randomUUID();

    private User user() {
        return new User(
                userId, UUID.randomUUID(), "user@example.com", "User", null, "SAML", "VIEWER", "ACTIVE", Instant.now(),
                true, null);
    }

    @Test
    void invalidCode_unauthorized_neverIssuesTokens() {
        when(handoffCodeRepository.consume("bad-code")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.exchange(new SsoExchangeController.ExchangeRequest("bad-code")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(401));
        verify(authenticationService, never()).issueTokens(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void userDeletedAfterCodeWasIssued_unauthorized() {
        when(handoffCodeRepository.consume("code")).thenReturn(Optional.of(userId));
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.exchange(new SsoExchangeController.ExchangeRequest("code")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(401));
    }

    @Test
    void validCode_mintsTokensAtExchangeTime_notBeforehand() {
        // The actual point of this test: a security review found tokens used to be minted ahead
        // of time and stored in sso_handoff_codes in plaintext - this confirms issueTokens is
        // only ever called here, at exchange, using the user looked up fresh from the consumed
        // code's userId, not any value read back from the handoff code itself (which no longer
        // carries tokens at all - see SsoHandoffCodeRepository's own javadoc).
        when(handoffCodeRepository.consume("code")).thenReturn(Optional.of(userId));
        User user = user();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        AuthResult result = new AuthResult(
                "access-token", 900, "refresh-token", UUID.randomUUID(), UserSummary.from(user));
        when(authenticationService.issueTokens(user)).thenReturn(result);

        var response = controller.exchange(new SsoExchangeController.ExchangeRequest("code"));

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.expiresIn()).isEqualTo(900);
        verify(authenticationService).issueTokens(user);
    }
}
