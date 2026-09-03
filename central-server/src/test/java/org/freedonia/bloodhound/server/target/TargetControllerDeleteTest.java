package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

/**
 * The hard-delete endpoint's two guard rails beyond ordinary write access -
 * ADMIN-only, and only reachable once a target is already soft-removed - are
 * what make it safe to expose from the UI at all (see TargetController#delete's
 * javadoc). Both are asserted here in isolation from the happy path.
 */
class TargetControllerDeleteTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final TargetAuthorizationRepository targetAuthorizationRepository = mock(TargetAuthorizationRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final TargetController controller = new TargetController(
            targetRepository, scanRunService, scoreSnapshotRepository, scanRunRepository, scanJobRepository,
            targetAuthorizationRepository, auditLogRepository, new TargetBulkCreateRateLimiter(), 100);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");
    private final JwtPrincipal analyst = new JwtPrincipal(UUID.randomUUID(), orgId, "ANALYST", "analyst@example.com");

    private Target target(boolean isActive) {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), isActive, Instant.now(), null);
    }

    @Test
    void analyst_cannotHardDelete_evenThoughTheyCanSoftRemove() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(false)));

        assertThatThrownBy(() -> controller.delete(targetId, analyst)).isInstanceOf(ResponseStatusException.class);
        verify(targetRepository, never()).delete(targetId);
    }

    @Test
    void admin_cannotHardDelete_stillActiveTarget_mustBeRemovedFirst() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(true)));

        assertThatThrownBy(() -> controller.delete(targetId, admin)).isInstanceOf(ResponseStatusException.class);
        verify(targetRepository, never()).delete(targetId);
    }

    @Test
    void admin_hardDeletesAlreadyRemovedTarget_succeeds() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(false)));

        ResponseEntity<Void> response = controller.delete(targetId, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(targetRepository).delete(targetId);
        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "TARGET_DELETED", "TARGET", targetId.toString(), "hostname=example.com");
    }

    @Test
    void admin_hardDelete_targetInAnotherOrg_notFound_neverLeaksExistence() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.delete(targetId, admin)).isInstanceOf(ResponseStatusException.class);
        verify(targetRepository, never()).delete(targetId);
    }
}
