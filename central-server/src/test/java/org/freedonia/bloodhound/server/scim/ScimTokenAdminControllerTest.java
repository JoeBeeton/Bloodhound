package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.scim.dto.CreateScimTokenRequest;
import org.freedonia.bloodhound.server.scim.dto.CreateScimTokenResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;

class ScimTokenAdminControllerTest {

    private final ScimTokenRepository repository = mock(ScimTokenRepository.class);
    private final ScimTokenAdminController controller = new ScimTokenAdminController(repository, "https://sp.example.com");

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private ScimToken saved(Instant expiresAt) {
        return new ScimToken(UUID.randomUUID(), orgId, "Okta", "hash", Instant.now(), null, expiresAt);
    }

    @Test
    void create_noExpiresInDays_neverExpires_notForcedLikeApiKeys() {
        // The deliberate design difference from API keys - see V44__scim_token_expiry.sql.
        when(repository.insert(eq(orgId), eq("Okta"), any(), isNull())).thenReturn(saved(null));

        ResponseEntity<CreateScimTokenResponse> response = controller.create(orgId, admin, new CreateScimTokenRequest("Okta", null));

        assertThat(response.getBody().expiresAt()).isNull();
        verify(repository).insert(eq(orgId), eq("Okta"), any(), isNull());
    }

    @Test
    void create_withExpiresInDays_computesExpiryFromNow() {
        Instant expected = Instant.now().plus(30, ChronoUnit.DAYS);
        when(repository.insert(eq(orgId), eq("Okta"), any(), any())).thenReturn(saved(expected));

        controller.create(orgId, admin, new CreateScimTokenRequest("Okta", 30));

        ArgumentCaptor<Instant> expiresAtCaptor = ArgumentCaptor.forClass(Instant.class);
        verify(repository).insert(eq(orgId), eq("Okta"), any(), expiresAtCaptor.capture());
        assertThat(expiresAtCaptor.getValue()).isCloseTo(expected, within(2, ChronoUnit.SECONDS));
    }
}
