package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingDetail;
import org.freedonia.bloodhound.server.findings.OrgFinding;
import org.freedonia.bloodhound.server.jobqueue.OrgScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanJobAttemptRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScansController;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

class McpReadToolsTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final SubdomainRepository subdomainRepository = mock(SubdomainRepository.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanJobAttemptRepository scanJobAttemptRepository = mock(ScanJobAttemptRepository.class);
    private final McpReadTools tools = new McpReadTools(
            targetRepository,
            findingRepository,
            subdomainRepository,
            scoreSnapshotRepository,
            scanRunRepository,
            scanJobRepository,
            scanJobAttemptRepository,
            new ObjectMapper());

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAsOrg(UUID org) {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("org_id", org.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(jwt, null));
    }

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "AUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void listTargets_usesOrgIdFromToken_notAnyCallerSuppliedValue() {
        authenticateAsOrg(orgId);
        when(targetRepository.findByOrganization(orgId, null, false)).thenReturn(List.of(target()));
        when(scoreSnapshotRepository.findLatest(targetId)).thenReturn(Optional.empty());

        List<TargetSummary> result = tools.listTargets(null, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname()).isEqualTo("example.com");
    }

    @Test
    void getTarget_targetBelongsToDifferentOrg_throwsIllegalArgument_notLeakingItsExistence() {
        authenticateAsOrg(orgId);
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tools.getTarget(targetId)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getTarget_ownedTarget_returnsSummary() {
        authenticateAsOrg(orgId);
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(scoreSnapshotRepository.findLatest(targetId)).thenReturn(Optional.empty());

        TargetSummary result = tools.getTarget(targetId);

        assertThat(result.id()).isEqualTo(targetId);
    }

    @Test
    void listFindingsForTarget_targetNotOwnedByCallerOrg_throwsBeforeQueryingFindings() {
        authenticateAsOrg(otherOrgId);
        when(targetRepository.findByIdAndOrganization(targetId, otherOrgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tools.listFindingsForTarget(targetId, null, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void listFindingsForTarget_ownedTarget_returnsFindings() {
        authenticateAsOrg(orgId);
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        Finding finding = new Finding(
                UUID.randomUUID(), "bh-example.com-1", UUID.randomUUID(), targetId, "HTTP_HEADERS", "RULE_1",
                "HIGH", "MISCONFIG", "Missing header", "desc", "{}", "example.com", UUID.randomUUID(), "OPEN",
                null, Instant.now(), Instant.now(), null);
        FindingDetail detail = new FindingDetail(finding, Instant.now(), "fix it");
        when(findingRepository.findByTargetDetailed(targetId, null, null, null, null, null, 200, 0))
                .thenReturn(List.of(detail));

        List<FindingSummary> result = tools.listFindingsForTarget(targetId, null, null, null, null, null, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).severity()).isEqualTo("HIGH");
    }

    @Test
    void listOpenFindingsForOrganization_usesTokenOrgId() {
        authenticateAsOrg(orgId);
        Finding finding = new Finding(
                UUID.randomUUID(), "bh-example.com-2", UUID.randomUUID(), targetId, "TLS_CHECK", "RULE_2",
                "CRITICAL", "TLS", "Expired cert", "desc", "{}", "example.com", UUID.randomUUID(), "OPEN",
                null, Instant.now(), Instant.now(), null);
        OrgFinding orgFinding = new OrgFinding(finding, "example.com", Instant.now(), null);
        when(findingRepository.findOpenByOrganization(orgId, List.of(), 50)).thenReturn(List.of(orgFinding));

        List<OrgFindingSummary> result = tools.listOpenFindingsForOrganization(null, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).targetHostname()).isEqualTo("example.com");
    }

    @Test
    void listOpenFindingsForOrganization_oversizedLimit_isClampedTo500() {
        // A security review found this was the one MCP tool of its shape with no upper bound at
        // all on limit (listFindingsForTarget/listSubdomains both already clamped) - an MCP client
        // could otherwise request Integer.MAX_VALUE rows across the whole org in one call.
        authenticateAsOrg(orgId);
        when(findingRepository.findOpenByOrganization(orgId, List.of(), 500)).thenReturn(List.of());

        tools.listOpenFindingsForOrganization(null, Integer.MAX_VALUE);

        org.mockito.Mockito.verify(findingRepository).findOpenByOrganization(orgId, List.of(), 500);
    }

    @Test
    void listRecentScans_mapsRunsForCallerOrg() {
        authenticateAsOrg(orgId);
        ScanRun run = new ScanRun(UUID.randomUUID(), targetId, "MANUAL", null, Instant.now(), null, "COMPLETE");
        when(scanRunRepository.findRecentByOrganization(orgId, 30)).thenReturn(List.of(new OrgScanRun(run, "example.com")));

        List<ScansController.RecentScan> result = tools.listRecentScans(null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).targetHostname()).isEqualTo("example.com");
    }

    @Test
    void listRecentScans_oversizedLimit_isClampedTo500() {
        // Same unbounded-limit gap as listOpenFindingsForOrganization, found in the same review -
        // this method had the identical shape (limit != null ? limit : 30, no upper bound).
        authenticateAsOrg(orgId);
        when(scanRunRepository.findRecentByOrganization(orgId, 500)).thenReturn(List.of());

        tools.listRecentScans(Integer.MAX_VALUE);

        org.mockito.Mockito.verify(scanRunRepository).findRecentByOrganization(orgId, 500);
    }

    @Test
    void getScanRun_runsTargetInDifferentOrg_throwsIllegalArgument() {
        authenticateAsOrg(orgId);
        UUID runId = UUID.randomUUID();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tools.getScanRun(runId)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void listActiveScans_mapsRunningRunsForCallerOrg() {
        authenticateAsOrg(orgId);
        ScanRun run = new ScanRun(UUID.randomUUID(), targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findRunningByOrganization(orgId)).thenReturn(List.of(new OrgScanRun(run, "example.com")));

        List<ScansController.RecentScan> result = tools.listActiveScans();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).targetHostname()).isEqualTo("example.com");
    }
}
