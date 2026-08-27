package org.freedonia.bloodhound.server.orgs;

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
import org.freedonia.bloodhound.server.orgs.dto.CreateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.CreateUserResponse;
import org.freedonia.bloodhound.server.orgs.dto.UpdateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class OrgUserControllerTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final OrgUserController controller = new OrgUserController(userRepository, passwordEncoder);

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final UUID adminUserId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(adminUserId, orgId, "ADMIN", "admin@example.com");

    private User user(UUID id, UUID org, String role, String status) {
        return new User(id, org, "u@example.com", "Name", "hash", "LOCAL", role, status, Instant.now());
    }

    @Test
    void list_orgIdMismatchesPrincipalsOrg_forbidden() {
        assertThatThrownBy(() -> controller.list(otherOrgId, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_matchingOrg_returnsUsers() {
        when(userRepository.findByOrganizationId(orgId)).thenReturn(List.of(user(UUID.randomUUID(), orgId, "VIEWER", "ACTIVE")));

        List<UserSummary> result = controller.list(orgId, admin);

        assertThat(result).hasSize(1);
    }

    @Test
    void create_orgIdMismatch_forbidden_neverInsertsUser() {
        assertThatThrownBy(() -> controller.create(otherOrgId, new CreateUserRequest("a@b.com", "A", "VIEWER"), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(userRepository, never()).insertLocalUser(any(), any(), any(), any(), any());
    }

    @Test
    void create_duplicateEmail_conflict() {
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(userRepository.insertLocalUser(eq(orgId), any(), any(), any(), any()))
                .thenThrow(new DataIntegrityViolationException("duplicate"));

        assertThatThrownBy(() -> controller.create(orgId, new CreateUserRequest("dup@example.com", "A", "VIEWER"), admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(409));
    }

    @Test
    void create_success_returnsTemporaryPasswordExactlyOnce() {
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        User created = user(UUID.randomUUID(), orgId, "VIEWER", "ACTIVE");
        when(userRepository.insertLocalUser(eq(orgId), eq("new@example.com"), eq("New Person"), eq("VIEWER"), any()))
                .thenReturn(created);

        ResponseEntity<CreateUserResponse> response =
                controller.create(orgId, new CreateUserRequest("new@example.com", "New Person", "VIEWER"), admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody().temporaryPassword()).isNotBlank();
        assertThat(response.getBody().user().id()).isEqualTo(created.id());
    }

    @Test
    void update_orgIdMismatch_forbidden() {
        assertThatThrownBy(() -> controller.update(otherOrgId, UUID.randomUUID(), new UpdateUserRequest("ADMIN", null), admin))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void update_targetUserInDifferentOrg_notFound_evenThoughUserIdExists() {
        UUID targetUserId = UUID.randomUUID();
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(user(targetUserId, otherOrgId, "VIEWER", "ACTIVE")));

        assertThatThrownBy(() -> controller.update(orgId, targetUserId, new UpdateUserRequest("ADMIN", null), admin))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void update_adminChangingOwnRole_forbidden_cannotLockSelfOut() {
        when(userRepository.findById(adminUserId)).thenReturn(Optional.of(user(adminUserId, orgId, "ADMIN", "ACTIVE")));

        assertThatThrownBy(() -> controller.update(orgId, adminUserId, new UpdateUserRequest("VIEWER", null), admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(403));
        verify(userRepository, never()).updateRoleAndStatus(any(), any(), any());
    }

    @Test
    void update_adminChangingOwnStatus_forbidden() {
        when(userRepository.findById(adminUserId)).thenReturn(Optional.of(user(adminUserId, orgId, "ADMIN", "ACTIVE")));

        assertThatThrownBy(() -> controller.update(orgId, adminUserId, new UpdateUserRequest(null, "SUSPENDED"), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(userRepository, never()).updateRoleAndStatus(any(), any(), any());
    }

    @Test
    void update_someoneElse_roleChanged_succeeds() {
        UUID targetUserId = UUID.randomUUID();
        User existing = user(targetUserId, orgId, "VIEWER", "ACTIVE");
        when(userRepository.findById(targetUserId))
                .thenReturn(Optional.of(existing))
                .thenReturn(Optional.of(user(targetUserId, orgId, "ANALYST", "ACTIVE")));
        when(userRepository.updateRoleAndStatus(targetUserId, "ANALYST", "ACTIVE")).thenReturn(true);

        UserSummary result = controller.update(orgId, targetUserId, new UpdateUserRequest("ANALYST", null), admin);

        assertThat(result.role()).isEqualTo("ANALYST");
        verify(userRepository).updateRoleAndStatus(targetUserId, "ANALYST", "ACTIVE");
    }

    @Test
    void update_partialUpdate_nullFieldsLeaveExistingValueUnchanged() {
        UUID targetUserId = UUID.randomUUID();
        User existing = user(targetUserId, orgId, "VIEWER", "ACTIVE");
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(existing));
        when(userRepository.updateRoleAndStatus(targetUserId, "VIEWER", "SUSPENDED")).thenReturn(true);

        controller.update(orgId, targetUserId, new UpdateUserRequest(null, "SUSPENDED"), admin);

        // role omitted (null) in the request - existing "VIEWER" must be preserved, not nulled out.
        verify(userRepository).updateRoleAndStatus(targetUserId, "VIEWER", "SUSPENDED");
    }

    @Test
    void update_wouldOrphanOrgWithNoActiveAdmin_conflict() {
        // The last-admin invariant is enforced atomically inside UserRepository's own UPDATE
        // (see its javadoc) - this test proves the controller surfaces that rejection as a
        // clean 409 rather than silently reporting success when zero rows were actually updated.
        UUID targetUserId = UUID.randomUUID();
        User existing = user(targetUserId, orgId, "ADMIN", "ACTIVE");
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(existing));
        when(userRepository.updateRoleAndStatus(targetUserId, "VIEWER", "ACTIVE")).thenReturn(false);

        assertThatThrownBy(() -> controller.update(orgId, targetUserId, new UpdateUserRequest("VIEWER", null), admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(409));
    }
}
