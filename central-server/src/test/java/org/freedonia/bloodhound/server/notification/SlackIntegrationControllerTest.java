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
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class SlackIntegrationControllerTest {

    private final SlackIntegrationRepository repository = mock(SlackIntegrationRepository.class);
    private final SlackNotifier slackNotifier = mock(SlackNotifier.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final SlackIntegrationController controller =
            new SlackIntegrationController(repository, slackNotifier, auditLogRepository, "https://app.example");

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

    @Test
    void test_noIntegrationConfigured_rejectedBeforeAnyDeliveryAttempt() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.test(orgId, admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
        verify(slackNotifier, never()).attemptDelivery(any(), any(), any(), any(), any());
    }

    @Test
    void test_deliverySucceeds_reportsSuccessWithNoDetail() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));
        when(slackNotifier.attemptDelivery(eq(REAL_URL), any(), any(), eq("INFO"), eq("https://app.example/dashboard")))
                .thenReturn(new SlackNotifier.DeliveryResult(true, null));

        SlackIntegrationController.TestSendResponse response = controller.test(orgId, admin);

        assertThat(response.success()).isTrue();
        assertThat(response.detail()).isNull();
    }

    @Test
    void test_deliveryFails_reportsFailureWithDetail_usingTheStoredUnmaskedUrl() {
        // The controller must pass the real, stored webhookUrl to SlackNotifier - never the masked
        // display value the frontend sees, which isn't a usable URL at all.
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));
        when(slackNotifier.attemptDelivery(eq(REAL_URL), any(), any(), any(), any()))
                .thenReturn(new SlackNotifier.DeliveryResult(false, "Slack responded with HTTP 404"));

        SlackIntegrationController.TestSendResponse response = controller.test(orgId, admin);

        assertThat(response.success()).isFalse();
        assertThat(response.detail()).isEqualTo("Slack responded with HTTP 404");
    }

    @Test
    void test_orgIdMismatch_forbidden_beforeAnyDeliveryAttempt() {
        UUID otherOrgId = UUID.randomUUID();

        assertThatThrownBy(() -> controller.test(otherOrgId, admin)).isInstanceOf(ResponseStatusException.class);
        verify(slackNotifier, never()).attemptDelivery(any(), any(), any(), any(), any());
    }

    @Test
    void save_recordsAuditEntry_withoutTheWebhookUrl() {
        // An audit review found configuring where scan/finding alerts get delivered - and, via
        // this endpoint's own validation, an SSRF-relevant surface - had no audit trail at all.
        String newUrl = "https://hooks.slack.com/services/T111/B111/newtoken";
        SlackIntegration saved = new SlackIntegration(
                UUID.randomUUID(), orgId, newUrl, true, List.of("NEW_FINDINGS"), false, Instant.now(), Instant.now());
        when(repository.upsert(orgId, newUrl, true, List.of("NEW_FINDINGS"), false)).thenReturn(saved);

        controller.save(orgId, admin, new SlackIntegrationController.SlackConfigRequest(newUrl, true, List.of("NEW_FINDINGS"), false));

        verify(auditLogRepository).record(
                eq(orgId), eq(admin.userId()), eq(admin.email()), eq("SLACK_INTEGRATION_SAVED"), eq("ORGANIZATION"), eq(orgId.toString()),
                org.mockito.ArgumentMatchers.argThat(detail -> !detail.contains("newtoken") && detail.contains("enabled=true")));
    }

    @Test
    void delete_recordsAuditEntry() {
        controller.delete(orgId, admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "SLACK_INTEGRATION_REMOVED", "ORGANIZATION", orgId.toString(), null);
    }
}
