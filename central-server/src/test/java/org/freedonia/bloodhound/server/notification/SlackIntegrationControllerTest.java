package org.freedonia.bloodhound.server.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class SlackIntegrationControllerTest {

    private final SlackIntegrationRepository repository = mock(SlackIntegrationRepository.class);
    private final SlackIntegrationController controller = new SlackIntegrationController(repository);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private static final String REAL_URL = "https://hooks.slack.com/services/T000/B000/realsecrettoken";

    private SlackIntegration existing() {
        return new SlackIntegration(
                UUID.randomUUID(), orgId, REAL_URL, true, List.of("NEW_FINDINGS"), false, Instant.now(), Instant.now());
    }

    @Test
    void get_neverReturnsTheRawWebhookUrl() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));

        ResponseEntity<SlackIntegrationController.SlackIntegrationResponse> response = controller.get(orgId, admin);

        String masked = response.getBody().webhookUrlMasked();
        assertThat(masked).doesNotContain("realsecrettoken");
        assertThat(masked).startsWith("https://hooks.slack.com/services/T000/B000/");
    }

    @Test
    void save_blankWebhookUrl_keepsExistingStoredUrl_notCleared() {
        // The frontend can never re-submit the real URL once it's been masked - a blank field on
        // an edit-in-place save must mean "leave the webhook as it is", not "wipe it out".
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));
        when(repository.upsert(eq(orgId), eq(REAL_URL), eq(true), any(), eq(false))).thenReturn(existing());

        controller.save(orgId, admin, new SlackIntegrationController.SlackConfigRequest("", true, List.of("NEW_FINDINGS"), false));

        verify(repository).upsert(orgId, REAL_URL, true, List.of("NEW_FINDINGS"), false);
    }

    @Test
    void save_blankWebhookUrl_noExistingIntegration_rejected() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.save(
                        orgId, admin, new SlackIntegrationController.SlackConfigRequest(null, true, List.of(), false)))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void save_invalidNewWebhookUrl_rejected_neverStored() {
        assertThatThrownBy(() -> controller.save(
                        orgId,
                        admin,
                        new SlackIntegrationController.SlackConfigRequest("https://evil.com/steal", true, List.of(), false)))
                .isInstanceOf(ResponseStatusException.class);
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void save_genuineNewWebhookUrl_stored_andResponseStillMasked() {
        String newUrl = "https://hooks.slack.com/services/T111/B111/newtoken";
        SlackIntegration saved = new SlackIntegration(
                UUID.randomUUID(), orgId, newUrl, true, List.of("NEW_FINDINGS"), false, Instant.now(), Instant.now());
        when(repository.upsert(orgId, newUrl, true, List.of("NEW_FINDINGS"), false)).thenReturn(saved);

        SlackIntegrationController.SlackIntegrationResponse response = controller.save(
                orgId, admin, new SlackIntegrationController.SlackConfigRequest(newUrl, true, List.of("NEW_FINDINGS"), false));

        verify(repository).upsert(orgId, newUrl, true, List.of("NEW_FINDINGS"), false);
        assertThat(response.webhookUrlMasked()).doesNotContain("newtoken");
    }
}
