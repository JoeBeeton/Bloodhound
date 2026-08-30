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
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.orgs.dto.ChangePasswordRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class UserSelfControllerTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final UserSelfController controller =
            new UserSelfController(userRepository, passwordEncoder, refreshTokenRepository);

    private final UUID userId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(userId, UUID.randomUUID(), "VIEWER", "u@example.com");

    private User user(String identitySource, String passwordHash) {
        return new User(
                userId, UUID.randomUUID(), "u@example.com", "Name", passwordHash, identitySource, "VIEWER", "ACTIVE",
                Instant.now(), true);
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
    void changePassword_nonLocalAccount_badRequest_neverRevokesTokens() {
        User existing = user("SAML", null);
        when(userRepository.findById(userId)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest("whatever", "new-pw"), principal))
                .isInstanceOf(ResponseStatusException.class);

        verify(refreshTokenRepository, never()).revokeAllForUser(any());
    }
}
