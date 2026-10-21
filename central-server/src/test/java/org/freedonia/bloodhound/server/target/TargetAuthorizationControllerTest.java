package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class TargetAuthorizationControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final TargetAuthorizationRepository authorizationRepository = mock(TargetAuthorizationRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final TargetAuthorizationController controller = new TargetAuthorizationController(
            targetRepository, authorizationRepository, auditLogRepository, scanJobRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");
    private final JwtPrincipal viewer = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target(String authStatus) {
        return new Target(targetId, orgId, "example.com", "OWN", authStatus, 3600, Instant.now(), true, Instant.now(), null);
    }

    private Target target(String targetType, String authStatus) {
        return new Target(targetId, orgId, "example.com", targetType, authStatus, 3600, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void get_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(targetId, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_returnsCurrentStatusAndHistory() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        var response = controller.get(targetId, admin);

        assertThat(response.authorizationStatus()).isEqualTo("AUTHORIZED");
        assertThat(response.history()).isEmpty();
    }

    @Test
    void authorize_viewerRole_forbidden_neverWritesAuthorization() {
        assertThatThrownBy(() -> controller.authorize(
                        targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), viewer))
                .isInstanceOf(ResponseStatusException.class);
        verify(authorizationRepository, never()).authorize(any(), any(), any());
    }

    @Test
    void authorize_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.authorize(
                        targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(authorizationRepository, never()).authorize(any(), any(), any());
    }

    @Test
    void authorize_admin_ownedTarget_writesAttestationAttributedToCaller() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        ResponseEntity<TargetAuthorizationController.AuthorizationStatusResponse> response =
                controller.authorize(targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody().authorizationStatus()).isEqualTo("AUTHORIZED");
        verify(authorizationRepository).authorize(targetId, admin.userId(), "I own this domain");
    }

    @Test
    void authorize_competitorTarget_forbidden_neverWritesAuthorization() {
        // The actual point of this test: a security review found this endpoint - the gate Tier 2
        // active scanning checks before it will ever touch a target - never checked targetType at
        // all, letting an ANALYST/ADMIN attest and deep-scan a COMPETITOR or WATCHLIST target
        // (i.e. a third party) despite the README/UI both treating Tier 2 as "OWN infrastructure
        // only."
        when(targetRepository.findByIdAndOrganization(targetId, orgId))
                .thenReturn(Optional.of(target("COMPETITOR", "UNAUTHORIZED")));

        assertThatThrownBy(() -> controller.authorize(
                        targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(403));
        verify(authorizationRepository, never()).authorize(any(), any(), any());
    }

    @Test
    void authorize_watchlistTarget_forbidden() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId))
                .thenReturn(Optional.of(target("WATCHLIST", "UNAUTHORIZED")));

        assertThatThrownBy(() -> controller.authorize(
                        targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(authorizationRepository, never()).authorize(any(), any(), any());
    }

    @Test
    void authorize_recordsAuditEntry() {
        // This flow already keeps its own detailed history (target_authorizations, surfaced via
        // GET above) - a security review found it wasn't also visible from the org-wide Audit Log
        // page, the one place an admin reviewing "everything sensitive that happened here" would
        // actually look.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        controller.authorize(targetId, new TargetAuthorizationController.AuthorizeRequest("I own this domain"), admin);

        verify(auditLogRepository).record(
                orgId, admin.userId(), admin.email(), "TARGET_AUTHORIZED", "TARGET", targetId.toString(), "hostname=example.com");
    }

    @Test
    void revoke_viewerRole_forbidden() {
        assertThatThrownBy(() -> controller.revoke(targetId, viewer)).isInstanceOf(ResponseStatusException.class);
        verify(authorizationRepository, never()).revokeCurrent(any(), any());
    }

    @Test
    void revoke_admin_ownedTarget_revokesAttributedToCaller() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        var response = controller.revoke(targetId, admin);

        assertThat(response.authorizationStatus()).isEqualTo("UNAUTHORIZED");
        verify(authorizationRepository).revokeCurrent(targetId, admin.userId());
    }

    @Test
    void revoke_cancelsAnyAlreadyQueuedTier2Jobs() {
        // A security review found revoke() flipped authorization_status but left already-queued
        // deep-scan jobs (PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN/BUCKET_BRUTE_FORCE) sitting in
        // the queue unchanged - they would still get claimed and run.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        controller.revoke(targetId, admin);

        verify(scanJobRepository).cancelNonTerminalTier2ForTarget(targetId, ScanRunService.allTier2ModuleTypes());
    }

    @Test
    void revoke_recordsAuditEntry() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(authorizationRepository.findHistory(targetId)).thenReturn(List.of());

        controller.revoke(targetId, admin);

        verify(auditLogRepository).record(
                orgId, admin.userId(), admin.email(), "TARGET_AUTHORIZATION_REVOKED", "TARGET", targetId.toString(),
                "hostname=example.com");
    }
}
