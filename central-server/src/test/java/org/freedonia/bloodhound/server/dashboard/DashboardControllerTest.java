package org.freedonia.bloodhound.server.dashboard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.OrgFinding;
import org.freedonia.bloodhound.server.jobqueue.OrgScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;

class DashboardControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final RuleWeightRepository ruleWeightRepository = mock(RuleWeightRepository.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DashboardController controller = new DashboardController(
            targetRepository, scoreSnapshotRepository, findingRepository, scanRunRepository, ruleWeightRepository, objectMapper);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target(String type) {
        return new Target(UUID.randomUUID(), orgId, "t-" + type + ".example.com", type, "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now());
    }

    private Finding finding(UUID id, UUID targetId, String evidenceJson) {
        return new Finding(
                id, UUID.randomUUID(), targetId, "HTTP", "RULE_X", "CRITICAL", "EXPOSURE", "title", "desc",
                evidenceJson, "asset", UUID.randomUUID(), "OPEN", null, Instant.now(), Instant.now());
    }

    private void stubEmptyBaseline() {
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), eq(10))).thenReturn(List.of());
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8))).thenReturn(List.of());
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
    }

    @Test
    void ownTargets_filteredToOwnTypeOnly() {
        Target own = target("OWN");
        Target competitor = target("COMPETITOR");
        Target watchlist = target("WATCHLIST");
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of(own, competitor, watchlist));
        when(scoreSnapshotRepository.findLatest(any())).thenReturn(java.util.Optional.empty());
        stubEmptyBaseline();

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.ownTargets()).hasSize(1);
        assertThat(summary.ownTargets().get(0).id()).isEqualTo(own.id());
    }

    @Test
    void stats_countEachTargetTypeCorrectly() {
        when(targetRepository.findByOrganization(orgId, null, false))
                .thenReturn(List.of(target("OWN"), target("OWN"), target("COMPETITOR"), target("WATCHLIST")));
        when(scoreSnapshotRepository.findLatest(any())).thenReturn(java.util.Optional.empty());
        stubEmptyBaseline();
        when(findingRepository.countOpenByOrganization(orgId, List.of("CRITICAL"))).thenReturn(3);
        when(findingRepository.countOpenByOrganization(orgId, List.of("HIGH"))).thenReturn(5);

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.stats().totalTargets()).isEqualTo(4);
        assertThat(summary.stats().ownCount()).isEqualTo(2);
        assertThat(summary.stats().competitorCount()).isEqualTo(1);
        assertThat(summary.stats().watchlistCount()).isEqualTo(1);
        assertThat(summary.stats().openCriticalCount()).isEqualTo(3);
        assertThat(summary.stats().openHighCount()).isEqualTo(5);
    }

    @Test
    void topFindings_scoreImpactContextFetchedOncePerTarget_notOncePerFinding() {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        UUID targetId = UUID.randomUUID();
        Finding f1 = finding(UUID.randomUUID(), targetId, null);
        Finding f2 = finding(UUID.randomUUID(), targetId, null);
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), eq(10)))
                .thenReturn(List.of(
                        new OrgFinding(f1, "host.example.com", Instant.now(), null),
                        new OrgFinding(f2, "host.example.com", Instant.now(), null)));
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8))).thenReturn(List.of());
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of(f1, f2));

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.topFindings()).hasSize(2);
        // Two findings sharing one target must only trigger one findOpenForScoring call for
        // that target's full context - this is exactly the O(n^2)-avoidance fix from this
        // session's performance work (computeIfAbsent caching by targetId).
        verify(findingRepository, times(1)).findOpenForScoring(targetId);
    }

    @Test
    void topFindings_evidenceJson_validJson_parsedIntoMap() throws Exception {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        UUID targetId = UUID.randomUUID();
        Finding f = finding(UUID.randomUUID(), targetId, "{\"key\":\"value\"}");
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), eq(10)))
                .thenReturn(List.of(new OrgFinding(f, "host.example.com", Instant.now(), null)));
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8))).thenReturn(List.of());
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of(f));

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.topFindings().get(0).evidence()).containsEntry("key", "value");
    }

    @Test
    void topFindings_evidenceJson_null_becomesEmptyMap() {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        UUID targetId = UUID.randomUUID();
        Finding f = finding(UUID.randomUUID(), targetId, null);
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), eq(10)))
                .thenReturn(List.of(new OrgFinding(f, "host.example.com", Instant.now(), null)));
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8))).thenReturn(List.of());
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of(f));

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.topFindings().get(0).evidence()).isEmpty();
    }

    @Test
    void topFindings_evidenceJson_malformed_becomesEmptyMap_doesNotThrow() {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        UUID targetId = UUID.randomUUID();
        Finding f = finding(UUID.randomUUID(), targetId, "{not valid json");
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), eq(10)))
                .thenReturn(List.of(new OrgFinding(f, "host.example.com", Instant.now(), null)));
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8))).thenReturn(List.of());
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of(f));

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.topFindings().get(0).evidence()).isEmpty();
    }

    @Test
    void recentActivity_mappedFromOrgScanRuns() {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        stubEmptyBaseline();
        UUID runId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        Instant started = Instant.now();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, started, null, "RUNNING");
        when(scanRunRepository.findRecentByOrganization(eq(orgId), eq(8)))
                .thenReturn(List.of(new OrgScanRun(run, "activity-host.example.com")));

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.recentActivity()).hasSize(1);
        DashboardSummary.RecentActivity activity = summary.recentActivity().get(0);
        assertThat(activity.id()).isEqualTo(runId);
        assertThat(activity.targetId()).isEqualTo(targetId);
        assertThat(activity.targetHostname()).isEqualTo("activity-host.example.com");
        assertThat(activity.status()).isEqualTo("RUNNING");
    }

    @Test
    void noTargetsNoFindings_returnsEmptyButWellFormedSummary() {
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of());
        stubEmptyBaseline();

        DashboardSummary summary = controller.get(principal);

        assertThat(summary.ownTargets()).isEmpty();
        assertThat(summary.topFindings()).isEmpty();
        assertThat(summary.recentActivity()).isEmpty();
        assertThat(summary.stats().totalTargets()).isZero();
    }
}
