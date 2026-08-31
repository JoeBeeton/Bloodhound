package org.freedonia.bloodhound.server.apikey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.apikey.dto.CreateApiKeyRequest;
import org.freedonia.bloodhound.server.apikey.dto.CreateApiKeyResponse;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class ApiKeyControllerTest {

    private final ApiKeyRepository apiKeyRepository = mock(ApiKeyRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final ApiKeyController controller = new ApiKeyController(apiKeyRepository, auditLogRepository);
    private final UUID orgId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private final JwtPrincipal viewer = new JwtPrincipal(userId, orgId, "VIEWER", "viewer@example.com");
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private ApiKey storedKey(String label, Instant expiresAt) {
        return new ApiKey(
                UUID.randomUUID(), orgId, userId, label, "bhk_abcdef", "somehash", Instant.now(), expiresAt, null, null);
    }

    /** Echoes back whatever label/keyPrefix/expiresAt the controller actually passed to insert(), like a real repository would. */
    private void stubInsertToEchoArguments() {
        when(apiKeyRepository.insert(eq(orgId), eq(userId), anyString(), anyString(), anyString(), any()))
                .thenAnswer(inv -> new ApiKey(
                        UUID.randomUUID(),
                        orgId,
                        userId,
                        inv.getArgument(2),
                        inv.getArgument(3),
                        inv.getArgument(4),
                        Instant.now(),
                        inv.getArgument(5),
                        null,
                        null));
    }

    @Test
    void create_defaultsExpiryWhenNotSpecified_andReturnsRawKeyOnce() {
        stubInsertToEchoArguments();

        ResponseEntity<CreateApiKeyResponse> response = controller.create(viewer, new CreateApiKeyRequest("ci-integration", null));

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        CreateApiKeyResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.apiKey()).startsWith("bhk_");
        assertThat(body.keyPrefix()).isEqualTo(body.apiKey().substring(0, 12));
        assertThat(body.expiresAt())
                .isCloseTo(Instant.now().plus(ApiKeyController.DEFAULT_EXPIRY_DAYS, ChronoUnit.DAYS), within2Minutes());
    }

    @Test
    void create_honorsExplicitExpiryInDays() {
        stubInsertToEchoArguments();

        ResponseEntity<CreateApiKeyResponse> response = controller.create(viewer, new CreateApiKeyRequest("short-lived", 7));

        assertThat(response.getBody().expiresAt())
                .isCloseTo(Instant.now().plus(7, ChronoUnit.DAYS), within2Minutes());
    }

    @Test
    void create_neverStoresTheRawKey_onlyItsHash() {
        stubInsertToEchoArguments();

        controller.create(viewer, new CreateApiKeyRequest("label", null));

        verify(apiKeyRepository)
                .insert(eq(orgId), eq(userId), eq("label"), anyString(), argThatIsNot64CharRawToken(), any());
    }

    private String argThatIsNot64CharRawToken() {
        // insert()'s 5th arg is the SHA-256 hex hash (64 hex chars), never the "bhk_"-prefixed raw token.
        return org.mockito.ArgumentMatchers.argThat(hash -> hash != null && hash.length() == 64 && !hash.startsWith("bhk_"));
    }

    @Test
    void list_returnsOnlyCallersOwnKeys() {
        when(apiKeyRepository.findByCreatedByUser(userId)).thenReturn(List.of(storedKey("a", Instant.now().plusSeconds(60))));

        var result = controller.list(viewer);

        assertThat(result).hasSize(1);
        verify(apiKeyRepository, never()).findByOrganization(any());
    }

    @Test
    void revoke_ownKey_succeeds() {
        UUID keyId = UUID.randomUUID();
        when(apiKeyRepository.revokeOwnedByUser(keyId, userId)).thenReturn(1);

        ResponseEntity<Void> response = controller.revoke(keyId, viewer);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(apiKeyRepository, never()).revokeWithinOrganization(any(), any());
    }

    @Test
    void revoke_notOwnKey_nonAdmin_returns404_neverFallsBackToOrgWideRevoke() {
        UUID keyId = UUID.randomUUID();
        when(apiKeyRepository.revokeOwnedByUser(keyId, userId)).thenReturn(0);

        assertThatThrownBy(() -> controller.revoke(keyId, viewer)).isInstanceOf(ResponseStatusException.class);
        verify(apiKeyRepository, never()).revokeWithinOrganization(any(), any());
    }

    @Test
    void revoke_notOwnKey_admin_fallsBackToOrgWideRevoke() {
        UUID keyId = UUID.randomUUID();
        UUID adminUserId = admin.userId();
        when(apiKeyRepository.revokeOwnedByUser(keyId, adminUserId)).thenReturn(0);
        when(apiKeyRepository.revokeWithinOrganization(keyId, orgId)).thenReturn(1);

        ResponseEntity<Void> response = controller.revoke(keyId, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
    }

    @Test
    void revoke_admin_keyNotInOrgEither_returns404() {
        UUID keyId = UUID.randomUUID();
        when(apiKeyRepository.revokeOwnedByUser(keyId, admin.userId())).thenReturn(0);
        when(apiKeyRepository.revokeWithinOrganization(keyId, orgId)).thenReturn(0);

        assertThatThrownBy(() -> controller.revoke(keyId, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void create_recordsAuditEntry_withLabelButNeverTheRawKeyOrHash() {
        // An audit review found minting/revoking these keys had no audit trail at all, unlike
        // ScimTokenAdminController's equivalent credential-lifecycle controller.
        stubInsertToEchoArguments();

        ResponseEntity<CreateApiKeyResponse> response = controller.create(viewer, new CreateApiKeyRequest("ci-integration", null));
        UUID createdId = response.getBody().id();

        verify(auditLogRepository).record(
                orgId, userId, viewer.email(), "API_KEY_CREATED", "API_KEY", createdId.toString(), "label=ci-integration");
    }

    @Test
    void revoke_recordsAuditEntry_withTheKeysLabel() {
        UUID keyId = UUID.randomUUID();
        ApiKey existing = new ApiKey(keyId, orgId, userId, "ci-integration", "bhk_abcdef", "hash", Instant.now(), null, null, null);
        when(apiKeyRepository.findByOrganization(orgId)).thenReturn(List.of(existing));
        when(apiKeyRepository.revokeOwnedByUser(keyId, userId)).thenReturn(1);

        controller.revoke(keyId, viewer);

        verify(auditLogRepository).record(
                orgId, userId, viewer.email(), "API_KEY_REVOKED", "API_KEY", keyId.toString(), "label=ci-integration");
    }

    @Test
    void revoke_unknownKey_notFound_neverRecordsAudit() {
        UUID keyId = UUID.randomUUID();
        when(apiKeyRepository.revokeOwnedByUser(keyId, userId)).thenReturn(0);

        assertThatThrownBy(() -> controller.revoke(keyId, viewer)).isInstanceOf(ResponseStatusException.class);
        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    private org.assertj.core.data.TemporalUnitOffset within2Minutes() {
        return org.assertj.core.api.Assertions.within(2, ChronoUnit.MINUTES);
    }
}
