package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.ActiveScan;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

class ScansControllerTest {

    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanJobAttemptRepository scanJobAttemptRepository = mock(ScanJobAttemptRepository.class);
    private final ScansController controller =
            new ScansController(scanRunRepository, scanJobRepository, scanJobAttemptRepository);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    @Test
    void active_noRunningScans_returnsEmptyList_neverQueriesEtaAverages() {
        when(scanRunRepository.findRunningByOrganization(orgId)).thenReturn(List.of());

        List<ActiveScan> result = controller.active(principal);

        assertThat(result).isEmpty();
        verify(scanJobAttemptRepository, never()).averageSecondsByModuleType(30);
    }

    @Test
    void active_etaAveragesFetchedOnce_sharedAcrossAllRunningScans_notOncePerRun() {
        UUID targetId1 = UUID.randomUUID();
        UUID targetId2 = UUID.randomUUID();
        UUID runId1 = UUID.randomUUID();
        UUID runId2 = UUID.randomUUID();
        ScanRun run1 = new ScanRun(runId1, targetId1, "MANUAL", null, Instant.now(), null, "RUNNING");
        ScanRun run2 = new ScanRun(runId2, targetId2, "SCHEDULED", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findRunningByOrganization(orgId))
                .thenReturn(List.of(new OrgScanRun(run1, "a.example.com"), new OrgScanRun(run2, "b.example.com")));
        when(scanJobRepository.findByScanRunId(runId1)).thenReturn(List.of());
        when(scanJobRepository.findByScanRunId(runId2)).thenReturn(List.of());
        when(scanJobAttemptRepository.averageSecondsByModuleType(30)).thenReturn(Map.of());

        List<ActiveScan> result = controller.active(principal);

        assertThat(result).hasSize(2);
        verify(scanJobAttemptRepository, org.mockito.Mockito.times(1)).averageSecondsByModuleType(30);
    }

    @Test
    void active_assemblesModuleProgressWithHostFromPayload() {
        UUID targetId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findRunningByOrganization(orgId)).thenReturn(List.of(new OrgScanRun(run, "a.example.com")));
        ScanJob job = new ScanJob(
                UUID.randomUUID(), runId, targetId, "HTTP_HEADERS", "RUNNING", (short) 0, Instant.now(), "worker-1",
                Instant.now(), Instant.now(), 1, 3, "{\"host\":\"a.example.com\"}", null, null, Instant.now());
        when(scanJobRepository.findByScanRunId(runId)).thenReturn(List.of(job));
        when(scanJobAttemptRepository.averageSecondsByModuleType(30)).thenReturn(Map.of());

        List<ActiveScan> result = controller.active(principal);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).modules()).hasSize(1);
        assertThat(result.get(0).modules().get(0).host()).isEqualTo("a.example.com");
        assertThat(result.get(0).targetHostname()).isEqualTo("a.example.com");
    }

    @Test
    void recent_mapsOrgScanRunsToRecentScanRecords_includingTerminalStatuses() {
        UUID targetId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), Instant.now(), "PARTIAL_FAILURE");
        when(scanRunRepository.findRecentByOrganization(eq(orgId), isNull(), eq(30), eq(0)))
                .thenReturn(List.of(new OrgScanRun(run, "c.example.com")));
        when(scanRunRepository.countRecentByOrganization(orgId, null)).thenReturn(1);

        ResponseEntity<List<ScansController.RecentScan>> response = controller.recent(principal, null, 30, 0);

        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).status()).isEqualTo("PARTIAL_FAILURE");
        assertThat(response.getBody().get(0).targetHostname()).isEqualTo("c.example.com");
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("1");
    }

    @Test
    void recent_limitPassedThroughToRepository() {
        when(scanRunRepository.findRecentByOrganization(eq(orgId), any(), eq(5), eq(0))).thenReturn(List.of());

        controller.recent(principal, null, 5, 0);

        verify(scanRunRepository).findRecentByOrganization(orgId, null, 5, 0);
    }

    @Test
    void recent_limitClampedToMax200() {
        when(scanRunRepository.findRecentByOrganization(eq(orgId), any(), eq(200), eq(0))).thenReturn(List.of());

        controller.recent(principal, null, 999999, 0);

        verify(scanRunRepository).findRecentByOrganization(orgId, null, 200, 0);
    }

    @Test
    void recent_negativeOffsetClampedToZero() {
        when(scanRunRepository.findRecentByOrganization(eq(orgId), any(), eq(30), eq(0))).thenReturn(List.of());

        controller.recent(principal, null, 30, -5);

        verify(scanRunRepository).findRecentByOrganization(orgId, null, 30, 0);
    }

    @Test
    void recent_statusFilter_passedThroughToRepositoryForBothQueryAndCount() {
        when(scanRunRepository.findRecentByOrganization(orgId, "FAILED", 30, 0)).thenReturn(List.of());
        when(scanRunRepository.countRecentByOrganization(orgId, "FAILED")).thenReturn(0);

        controller.recent(principal, "FAILED", 30, 0);

        verify(scanRunRepository).findRecentByOrganization(orgId, "FAILED", 30, 0);
        verify(scanRunRepository).countRecentByOrganization(orgId, "FAILED");
    }
}
