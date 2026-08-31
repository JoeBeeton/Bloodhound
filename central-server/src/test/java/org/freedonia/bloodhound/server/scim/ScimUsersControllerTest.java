package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.scim.dto.ScimPatchOperation;
import org.freedonia.bloodhound.server.scim.dto.ScimPatchRequest;
import org.freedonia.bloodhound.server.scim.dto.ScimUserWriteRequest;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

/**
 * No test coverage existed for this controller before this - added alongside the audit-logging
 * fix specifically to lock in that a SCIM-driven active/inactive transition (the actual
 * account-provisioning execution path an external IdP uses) now lands in the shared Audit Log,
 * attributed to the SCIM token's own label rather than a human actor.
 */
class ScimUsersControllerTest {

    private final ScimUserRepository scimUserRepository = mock(ScimUserRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final ScimUsersController controller =
            new ScimUsersController(scimUserRepository, auditLogRepository, "https://sp.example.com");

    private final UUID orgId = UUID.randomUUID();
    private final ScimPrincipal principal = new ScimPrincipal(orgId, "Okta");

    private ScimUserRow row(UUID id, String userName, boolean active) {
        return new ScimUserRow(id, orgId, userName, userName, active, null, Instant.now(), Instant.now());
    }

    @Test
    void create_recordsAudit_attributedToTheScimTokensOwnLabel_noHumanActor() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.insert(orgId, "alice", "", true, null)).thenReturn(row(userId, "alice", true));

        controller.create(principal, new ScimUserWriteRequest(null, "alice", null, null, true));

        verify(auditLogRepository).record(
                orgId, null, "SCIM: Okta", "SCIM_USER_CREATED", "USER", userId.toString(), "userName=alice");
    }

    @Test
    void replace_activeFlippedToFalse_recordsDeactivated() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId))
                .thenReturn(Optional.of(row(userId, "alice", true)))
                .thenReturn(Optional.of(row(userId, "alice", false)));

        controller.replace(principal, userId, new ScimUserWriteRequest(null, "alice", null, null, false));

        verify(auditLogRepository)
                .record(orgId, null, "SCIM: Okta", "SCIM_USER_DEACTIVATED", "USER", userId.toString(), null);
    }

    @Test
    void replace_activeUnchanged_doesNotRecordAudit() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", true)));

        controller.replace(principal, userId, new ScimUserWriteRequest(null, "alice", null, null, true));

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void patch_activateOperation_recordsActivated() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", false)));
        ScimPatchRequest request =
                new ScimPatchRequest(List.of(), List.of(new ScimPatchOperation("replace", "active", true)));

        controller.patch(principal, userId, request);

        verify(auditLogRepository)
                .record(orgId, null, "SCIM: Okta", "SCIM_USER_ACTIVATED", "USER", userId.toString(), null);
    }

    @Test
    void patch_displayNameOnly_neverRecordsAudit() {
        // A profile-only sync via SCIM isn't a security-relevant state transition - only the
        // active flip is audit-worthy, same restraint the isActive/mcpEnabled fixes elsewhere in
        // this app already apply.
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", true)));
        ScimPatchRequest request =
                new ScimPatchRequest(List.of(), List.of(new ScimPatchOperation("replace", "displayName", "Alice B")));

        controller.patch(principal, userId, request);

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void deactivate_activeUser_recordsDeactivated() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", true)));

        controller.deactivate(principal, userId);

        verify(auditLogRepository)
                .record(orgId, null, "SCIM: Okta", "SCIM_USER_DEACTIVATED", "USER", userId.toString(), null);
    }

    @Test
    void create_oversizedUserName_rejectedBeforeTouchingTheRepository() {
        // A security review found none of userName/displayName/externalId had any length cap at
        // all, anywhere - a compromised SCIM token or misconfigured IdP could otherwise push
        // arbitrary-size text into the shared users table's email/display_name columns.
        String tooLong = "a".repeat(321);

        assertThatThrownBy(() -> controller.create(principal, new ScimUserWriteRequest(null, tooLong, null, null, true)))
                .isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(scimUserRepository);
    }

    @Test
    void create_oversizedDisplayName_rejectedBeforeTouchingTheRepository() {
        String tooLong = "a".repeat(201);

        assertThatThrownBy(() -> controller.create(
                        principal, new ScimUserWriteRequest(null, "alice", null, tooLong, true)))
                .isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(scimUserRepository);
    }

    @Test
    void create_oversizedExternalId_rejectedBeforeTouchingTheRepository() {
        String tooLong = "a".repeat(201);

        assertThatThrownBy(() -> controller.create(
                        principal, new ScimUserWriteRequest(tooLong, "alice", null, null, true)))
                .isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(scimUserRepository);
    }

    @Test
    void create_exactlyAtTheCap_isAccepted_notOffByOne() {
        String exactly200 = "a".repeat(200);
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.insert(orgId, "alice", exactly200, true, null)).thenReturn(row(userId, "alice", true));

        controller.create(principal, new ScimUserWriteRequest(null, "alice", null, exactly200, true));

        verify(scimUserRepository).insert(orgId, "alice", exactly200, true, null);
    }

    @Test
    void patch_oversizedUserNameViaPathlessBulkForm_rejectedBeforeTouchingTheRepository() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", true)));
        String tooLong = "a".repeat(321);
        ScimPatchRequest request =
                new ScimPatchRequest(List.of(), List.of(new ScimPatchOperation("replace", "userName", tooLong)));

        assertThatThrownBy(() -> controller.patch(principal, userId, request))
                .isInstanceOf(ResponseStatusException.class);
        verify(scimUserRepository, never()).updateUserName(any(), any(), any());
    }

    @Test
    void deactivate_alreadyInactiveUser_doesNotRecordAudit() {
        UUID userId = UUID.randomUUID();
        when(scimUserRepository.findByOrgAndId(orgId, userId)).thenReturn(Optional.of(row(userId, "alice", false)));

        controller.deactivate(principal, userId);

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }
}
