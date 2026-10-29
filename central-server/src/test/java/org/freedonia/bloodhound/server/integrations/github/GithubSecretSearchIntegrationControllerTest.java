package org.freedonia.bloodhound.server.integrations.github;

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
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.SecretCredentialCipher;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class GithubSecretSearchIntegrationControllerTest {

    private final GithubSecretSearchIntegrationRepository repository = mock(GithubSecretSearchIntegrationRepository.class);
    private final SecretCredentialCipher cipher = mock(SecretCredentialCipher.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final GithubSecretSearchIntegrationController controller =
            new GithubSecretSearchIntegrationController(repository, cipher, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private static final String REAL_TOKEN = "ghp_realtokenvalue1234567890abcdef";

    private GithubSecretSearchIntegration existing() {
        return new GithubSecretSearchIntegration(
                UUID.randomUUID(), orgId, new byte[] {1, 2, 3}, true, Instant.now(), Instant.now());
    }

    @Test
    void get_neverCallsTheCipher_noDecryptionJustToDisplayTheIntegration() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));

        ResponseEntity<?> response = controller.get(orgId, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        var body = (GithubSecretSearchIntegrationController.IntegrationResponse) response.getBody();
        assertThat(body.enabled()).isTrue();
        verify(cipher, never()).decrypt(any());
    }

    @Test
    void get_noneConfigured_returns204() {
        when(repository.findByOrganization(orgId)).thenReturn(Optional.empty());

        assertThat(controller.get(orgId, admin).getStatusCode().value()).isEqualTo(204);
    }

    @Test
    void save_encryptionNotConfigured_rejectedBeforeAnyRepositoryCall() {
        when(cipher.isConfigured()).thenReturn(false);

        ResponseEntity<?> response = controller.save(
                orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest(REAL_TOKEN, true));

        assertThat(response.getStatusCode().value()).isEqualTo(503);
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void save_blankToken_noExistingIntegration_rejected() {
        when(cipher.isConfigured()).thenReturn(true);
        when(repository.findByOrganization(orgId)).thenReturn(Optional.empty());

        ResponseEntity<?> response =
                controller.save(orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest(null, true));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(((GithubSecretSearchIntegrationController.ErrorMessageResponse) response.getBody()).message())
                .isEqualTo("token is required");
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void save_blankToken_existingIntegration_onlyTogglesEnabled_neverDecryptsOrReEncrypts() {
        when(cipher.isConfigured()).thenReturn(true);
        when(repository.findByOrganization(orgId)).thenReturn(Optional.of(existing()));

        controller.save(orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest("", false));

        verify(repository).updateEnabledOnly(orgId, false);
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean());
        verify(cipher, never()).decrypt(any());
        verify(cipher, never()).encrypt(any());
    }

    @Test
    void save_tokenTooShort_rejected_neverStored() {
        when(cipher.isConfigured()).thenReturn(true);

        ResponseEntity<?> response =
                controller.save(orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest("short", true));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void save_genuineNewToken_storedViaRepository() {
        when(cipher.isConfigured()).thenReturn(true);
        when(repository.upsert(orgId, REAL_TOKEN, true)).thenReturn(existing());

        controller.save(orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest(REAL_TOKEN, true));

        verify(repository).upsert(orgId, REAL_TOKEN, true);
    }

    @Test
    void save_recordsAuditEntry_withoutTheToken() {
        when(cipher.isConfigured()).thenReturn(true);
        when(repository.upsert(orgId, REAL_TOKEN, true)).thenReturn(existing());

        controller.save(orgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest(REAL_TOKEN, true));

        verify(auditLogRepository)
                .record(
                        eq(orgId),
                        eq(admin.userId()),
                        eq(admin.email()),
                        eq("GITHUB_SECRET_SEARCH_INTEGRATION_SAVED"),
                        eq("ORGANIZATION"),
                        eq(orgId.toString()),
                        org.mockito.ArgumentMatchers.argThat(
                                detail -> !detail.contains(REAL_TOKEN) && detail.contains("enabled=true")));
    }

    @Test
    void save_orgIdMismatch_notFound_beforeAnyRepositoryCall() {
        UUID otherOrgId = UUID.randomUUID();

        assertThatThrownBy(() -> controller.save(
                        otherOrgId, admin, new GithubSecretSearchIntegrationController.IntegrationRequest(REAL_TOKEN, true)))
                .isInstanceOf(ResponseStatusException.class);
        verify(repository, never()).upsert(any(), any(), org.mockito.Mockito.anyBoolean());
    }

    @Test
    void delete_recordsAuditEntry() {
        controller.delete(orgId, admin);

        verify(auditLogRepository)
                .record(
                        orgId,
                        admin.userId(),
                        admin.email(),
                        "GITHUB_SECRET_SEARCH_INTEGRATION_REMOVED",
                        "ORGANIZATION",
                        orgId.toString(),
                        null);
    }
}
