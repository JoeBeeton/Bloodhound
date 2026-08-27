package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
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
        when(scanRunRepository.findRecentByOrganization(orgId, 30)).thenReturn(List.of(new OrgScanRun(run, "c.example.com")));

        List<ScansController.RecentScan> result = controller.recent(principal, 30);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).status()).isEqualTo("PARTIAL_FAILURE");
        assertThat(result.get(0).targetHostname()).isEqualTo("c.example.com");
    }

    @Test
    void recent_limitPassedThroughToRepository() {
        when(scanRunRepository.findRecentByOrganization(orgId, 5)).thenReturn(List.of());

        controller.recent(principal, 5);

        verify(scanRunRepository).findRecentByOrganization(orgId, 5);
    }
}
