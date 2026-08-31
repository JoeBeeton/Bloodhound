package org.freedonia.bloodhound.server.findings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class FindingControllerTest {

    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final RuleWeightRepository ruleWeightRepository = mock(RuleWeightRepository.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final FindingController controller = new FindingController(
            findingRepository, targetRepository, scanRunRepository, ruleWeightRepository, objectMapper, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");
    private final JwtPrincipal analyst = new JwtPrincipal(UUID.randomUUID(), orgId, "ANALYST", "analyst@example.com");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
    }

    private Finding finding(UUID id) {
        return finding(id, "OPEN");
    }

    private Finding finding(UUID id, String status) {
        return new Finding(
                id, "bh-test-1", UUID.randomUUID(), targetId, "HTTP", "RULE_X", "HIGH", "EXPOSURE", "title", "desc", null,
                "asset", UUID.randomUUID(), status, null, Instant.now(), Instant.now());
    }

    private void stubCommonListDeps() {
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of());
        when(findingRepository.countByTargetFiltered(eq(targetId), any(), any(), any(), any(), any())).thenReturn(0);
        when(findingRepository.findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(List.of());
    }

    @Test
    void forTarget_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.forTarget(targetId, null, null, null, null, null, 200, 0, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void forTarget_ownedTarget_returnsPageWithTotalCountHeader() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();
        when(findingRepository.countByTargetFiltered(targetId, null, null, null, null, null)).thenReturn(42);

        ResponseEntity<List<FindingSummary>> response =
                controller.forTarget(targetId, null, null, null, null, null, 200, 0, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("42");
    }

    @Test
    void forTarget_limitClampedToMax500_evenIfCallerAsksForMore() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();

        controller.forTarget(targetId, null, null, null, null, null, 999999, 0, principal);

        verify(findingRepository).findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), eq(500), eq(0));
    }

    @Test
    void forTarget_limitClampedToMin1_evenIfCallerAsksForZeroOrNegative() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();

        controller.forTarget(targetId, null, null, null, null, null, -5, 0, principal);

        verify(findingRepository).findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), eq(1), eq(0));
    }

    @Test
    void forTarget_negativeOffset_clampedToZero() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();

        controller.forTarget(targetId, null, null, null, null, null, 200, -10, principal);

        verify(findingRepository).findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), anyInt(), eq(0));
    }

    @Test
    void forTarget_searchFilter_passedThroughToRepository() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();

        controller.forTarget(targetId, null, null, null, null, "csp", 200, 0, principal);

        verify(findingRepository).findByTargetDetailed(targetId, null, null, null, null, "csp", 200, 0);
    }

    @Test
    void exportForTarget_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.exportForTarget(targetId, null, null, null, null, null, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void exportForTarget_ownedTarget_returnsCsvWithAttachmentHeader() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), anyInt(), eq(0)))
                .thenReturn(List.of(new FindingDetail(finding(UUID.randomUUID()), Instant.now(), "fix it")));

        ResponseEntity<byte[]> response = controller.exportForTarget(targetId, null, null, null, null, null, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentDisposition().isAttachment()).isTrue();
        assertThat(response.getHeaders().getContentDisposition().getFilename()).contains("example.com").endsWith(".csv");
        String csv = new String(response.getBody(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csv).contains("bh-test-1").contains("fix it");
    }

    @Test
    void exportForTarget_usesAGenerousBoundedLimit_notTheDisplayPageLimit() {
        // Export is meant to mean "everything matching the filter", not just one browsable page
        // (see MAX_EXPORT_LIMIT's javadoc) - this locks in that it asks the repository for far
        // more rows than the interactive list endpoints ever do (MAX_FINDINGS_LIMIT there is 500).
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), anyInt(), eq(0)))
                .thenReturn(List.of());

        controller.exportForTarget(targetId, "HIGH", "EXPOSURE", "OPEN", "asset.example.com", null, principal);

        verify(findingRepository)
                .findByTargetDetailed(targetId, "HIGH", "EXPOSURE", "OPEN", "asset.example.com", null, 50_000, 0);
    }

    @Test
    void forRun_runNotFound_notFound() {
        UUID runId = UUID.randomUUID();
        when(scanRunRepository.findById(runId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.forRun(runId, null, null, null, null, null, 200, 0, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void forRun_runsTargetInAnotherOrg_notFound() {
        UUID runId = UUID.randomUUID();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.forRun(runId, null, null, null, null, null, 200, 0, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void forRun_resolvesRunsTarget_thenListsThatTargetsCurrentFindings() {
        UUID runId = UUID.randomUUID();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        stubCommonListDeps();

        ResponseEntity<List<FindingSummary>> response =
                controller.forRun(runId, null, null, null, null, null, 200, 0, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(findingRepository).findByTargetDetailed(eq(targetId), any(), any(), any(), any(), any(), eq(200), eq(0));
    }

    @Test
    void forOrganization_scoreImpactContextFetchedOncePerTarget() {
        Finding f1 = finding(UUID.randomUUID());
        Finding f2 = finding(UUID.randomUUID());
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(20), eq(0)))
                .thenReturn(List.of(
                        new OrgFinding(f1, "host.example.com", Instant.now(), null),
                        new OrgFinding(f2, "host.example.com", Instant.now(), null)));
        when(ruleWeightRepository.findAllWeights()).thenReturn(Map.of());
        when(findingRepository.findOpenForScoring(targetId)).thenReturn(List.of(f1, f2));
        when(findingRepository.countOpenByOrganizationFiltered(eq(orgId), any(), any(), any(), any())).thenReturn(2);

        ResponseEntity<List<OrgFindingSummary>> response =
                controller.forOrganization(null, null, null, null, 20, 0, principal);

        assertThat(response.getBody()).hasSize(2);
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("2");
        verify(findingRepository, org.mockito.Mockito.times(1)).findOpenForScoring(targetId);
    }

    @Test
    void forOrganization_severityAndCategoryFilters_splitOnComma() {
        when(findingRepository.findOpenByOrganization(
                        eq(orgId), eq(List.of("CRITICAL", "HIGH")), eq(List.of("EXPOSURE")), any(), any(), eq(20), eq(0)))
                .thenReturn(List.of());

        controller.forOrganization("CRITICAL,HIGH", "EXPOSURE", null, null, 20, 0, principal);

        verify(findingRepository)
                .findOpenByOrganization(orgId, List.of("CRITICAL", "HIGH"), List.of("EXPOSURE"), null, null, 20, 0);
    }

    @Test
    void forOrganization_blankFilters_meansNoFilter() {
        when(findingRepository.findOpenByOrganization(eq(orgId), eq(List.of()), eq(List.of()), any(), any(), eq(20), eq(0)))
                .thenReturn(List.of());

        controller.forOrganization("", "", null, null, 20, 0, principal);

        verify(findingRepository).findOpenByOrganization(orgId, List.of(), List.of(), null, null, 20, 0);
    }

    @Test
    void forOrganization_statusFilter_passedThroughToRepository() {
        // The only way anywhere in the app to see resolved findings across the whole org - a
        // product review found no page (or even query param) let a caller ask for anything but
        // OPEN, despite the target-scoped endpoint already supporting it.
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), eq("RESOLVED"), any(), eq(20), eq(0)))
                .thenReturn(List.of());

        controller.forOrganization(null, null, "RESOLVED", null, 20, 0, principal);

        verify(findingRepository).findOpenByOrganization(orgId, List.of(), List.of(), "RESOLVED", null, 20, 0);
    }

    @Test
    void forOrganization_searchFilter_passedThroughToRepository() {
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), any(), eq("csp"), eq(20), eq(0)))
                .thenReturn(List.of());
        when(findingRepository.countOpenByOrganizationFiltered(eq(orgId), any(), any(), any(), eq("csp")))
                .thenReturn(0);

        controller.forOrganization(null, null, null, "csp", 20, 0, principal);

        verify(findingRepository).findOpenByOrganization(orgId, List.of(), List.of(), null, "csp", 20, 0);
        verify(findingRepository).countOpenByOrganizationFiltered(orgId, List.of(), List.of(), null, "csp");
    }

    @Test
    void forOrganization_limitClampedToMax500_evenIfCallerAsksForMore() {
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(500), eq(0)))
                .thenReturn(List.of());

        controller.forOrganization(null, null, null, null, 999999, 0, principal);

        verify(findingRepository).findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(500), eq(0));
    }

    @Test
    void forOrganization_negativeOffset_clampedToZero() {
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(20), eq(0)))
                .thenReturn(List.of());

        controller.forOrganization(null, null, null, null, 20, -5, principal);

        verify(findingRepository).findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(20), eq(0));
    }

    @Test
    void exportForOrganization_returnsCsvWithAttachmentHeader_includingTargetColumn() {
        Finding f = finding(UUID.randomUUID());
        when(findingRepository.findOpenByOrganization(eq(orgId), any(), any(), any(), any(), eq(50_000), eq(0)))
                .thenReturn(List.of(new OrgFinding(f, "host.example.com", Instant.now(), "fix it")));

        ResponseEntity<byte[]> response = controller.exportForOrganization(null, null, null, null, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentDisposition().isAttachment()).isTrue();
        assertThat(response.getHeaders().getContentDisposition().getFilename()).endsWith(".csv");
        String csv = new String(response.getBody(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csv).contains("Target,Display ID").contains("host.example.com").contains("bh-test-1");
    }

    @Test
    void exportForOrganization_passesFiltersThrough_unboundedByTheDisplayPageLimit() {
        when(findingRepository.findOpenByOrganization(
                        eq(orgId), eq(List.of("CRITICAL")), eq(List.of("EXPOSURE")), eq("RESOLVED"), eq("csp"), eq(50_000), eq(0)))
                .thenReturn(List.of());

        controller.exportForOrganization("CRITICAL", "EXPOSURE", "RESOLVED", "csp", principal);

        verify(findingRepository)
                .findOpenByOrganization(orgId, List.of("CRITICAL"), List.of("EXPOSURE"), "RESOLVED", "csp", 50_000, 0);
    }

    @Test
    void dismissFinding_viewerRole_forbidden_neverMutates() {
        assertThatThrownBy(() -> controller.dismissFinding(UUID.randomUUID(), principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(403));
        verify(findingRepository, org.mockito.Mockito.never()).dismiss(any());
    }

    @Test
    void dismissFinding_notFound_404() {
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.dismissFinding(findingId, analyst)).isInstanceOf(ResponseStatusException.class);
        verify(findingRepository, org.mockito.Mockito.never()).dismiss(any());
    }

    @Test
    void dismissFinding_targetInAnotherOrg_404_neverMutates() {
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding(findingId)));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.dismissFinding(findingId, analyst)).isInstanceOf(ResponseStatusException.class);
        verify(findingRepository, org.mockito.Mockito.never()).dismiss(any());
    }

    @Test
    void dismissFinding_openFinding_succeeds_recordsAudit() {
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding(findingId)));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.dismiss(findingId)).thenReturn(1);

        ResponseEntity<?> response = controller.dismissFinding(findingId, analyst);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(auditLogRepository).record(
                eq(orgId), eq(analyst.userId()), eq(analyst.email()), eq("FINDING_DISMISSED"), eq("FINDING"),
                eq(findingId.toString()), any());
    }

    @Test
    void dismissFinding_notActuallyOpen_conflictWithARealMessage_neverRecordsAudit() {
        // dismiss() only transitions FROM OPEN (see FindingRepository#dismiss's own javadoc for
        // why DISMISSED is a sticky override on an otherwise-open finding specifically), so a
        // caller can't re-dismiss an already-dismissed one or dismiss one that resolved itself in
        // the same moment. A real response body, not a thrown ResponseStatusException, since this
        // app's default error handler never exposes a ResponseStatusException's reason text.
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding(findingId, "RESOLVED")));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.dismiss(findingId)).thenReturn(0);

        ResponseEntity<?> response = controller.dismissFinding(findingId, analyst);

        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(((FindingController.ErrorMessageResponse) response.getBody()).message()).contains("open finding");
        verify(auditLogRepository, org.mockito.Mockito.never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void reopenFinding_dismissedFinding_succeeds_recordsAudit() {
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding(findingId, "DISMISSED")));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.reopen(findingId)).thenReturn(1);

        ResponseEntity<?> response = controller.reopenFinding(findingId, analyst);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(auditLogRepository).record(
                eq(orgId), eq(analyst.userId()), eq(analyst.email()), eq("FINDING_REOPENED"), eq("FINDING"),
                eq(findingId.toString()), any());
    }

    @Test
    void reopenFinding_notActuallyDismissed_conflictWithARealMessage() {
        UUID findingId = UUID.randomUUID();
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding(findingId, "OPEN")));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(findingRepository.reopen(findingId)).thenReturn(0);

        ResponseEntity<?> response = controller.reopenFinding(findingId, analyst);

        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(((FindingController.ErrorMessageResponse) response.getBody()).message()).contains("dismissed finding");
    }
}
