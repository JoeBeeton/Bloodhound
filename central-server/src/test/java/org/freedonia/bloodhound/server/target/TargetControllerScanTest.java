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
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

/**
 * Neither /scan nor /scan/deep had any test coverage before this - in particular, neither had
 * ever checked whether a scan was already running for the target, the same race
 * ScanAutoScheduler already guards its own cadence-driven scans against (see
 * ScanRunRepository#existsRunningForTarget's javadoc). That gap became a real, not just
 * theoretical, concern once TargetsPage's bulk "Scan N selected" action started firing many of
 * these requests in parallel.
 */
class TargetControllerScanTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final TargetController controller = new TargetController(
            targetRepository, scanRunService, scoreSnapshotRepository, scanRunRepository, scanJobRepository, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");
    private final JwtPrincipal viewer = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target(String authorizationStatus) {
        return new Target(targetId, orgId, "example.com", "OWN", authorizationStatus, 3600, Instant.now(), true, Instant.now(), null);
    }

    private ScanRun run() {
        return new ScanRun(UUID.randomUUID(), targetId, "MANUAL", admin.userId(), Instant.now(), null, "RUNNING");
    }

    @Test
    void scanNow_noRunInFlight_succeeds() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(false);
        when(scanRunService.createManualScan(targetId, admin.userId())).thenReturn(run());

        ResponseEntity<TargetController.ScanRunSummary> response = controller.scanNow(targetId, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    void scanNow_runAlreadyInFlight_conflict_neverCreatesASecondRun() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("UNAUTHORIZED")));
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(true);

        assertThatThrownBy(() -> controller.scanNow(targetId, admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(409));
        verify(scanRunService, never()).createManualScan(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void scanNow_viewerRole_forbidden_neverChecksInFlightOrCreatesARun() {
        assertThatThrownBy(() -> controller.scanNow(targetId, viewer)).isInstanceOf(ResponseStatusException.class);
        verify(scanRunRepository, never()).existsRunningForTarget(org.mockito.ArgumentMatchers.any());
        verify(scanRunService, never()).createManualScan(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void scanNow_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.scanNow(targetId, admin)).isInstanceOf(ResponseStatusException.class);
        verify(scanRunService, never()).createManualScan(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void deepScanNow_authorizedAndNoRunInFlight_succeeds() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(false);
        when(scanRunService.createDeepScan(targetId, admin.userId())).thenReturn(run());

        ResponseEntity<TargetController.ScanRunSummary> response = controller.deepScanNow(targetId, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    void deepScanNow_runAlreadyInFlight_conflict() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("AUTHORIZED")));
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(true);

        assertThatThrownBy(() -> controller.deepScanNow(targetId, admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(409));
        verify(scanRunService, never()).createDeepScan(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void deepScanNow_notAuthorized_forbidden_beforeEverCheckingInFlightState() {
        // The authorization failure is the more informative thing to report - an unauthorized
        // target reads as "you need to authorize this first," not "try again later."
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("UNAUTHORIZED")));

        assertThatThrownBy(() -> controller.deepScanNow(targetId, admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(403));
        verify(scanRunRepository, never()).existsRunningForTarget(org.mockito.ArgumentMatchers.any());
        verify(scanRunService, never()).createDeepScan(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }
}
