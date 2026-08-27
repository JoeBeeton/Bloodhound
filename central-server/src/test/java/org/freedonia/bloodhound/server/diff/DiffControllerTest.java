package org.freedonia.bloodhound.server.diff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.diff.dto.FindingDiffResponse;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class DiffControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final DiffController controller =
            new DiffController(targetRepository, scanRunRepository, findingRepository, new ObjectMapper());

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID runId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now());
    }

    @Test
    void diff_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.diff(targetId, runId, "previous", principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void diff_runDoesNotBelongToTarget_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        UUID otherTargetId = UUID.randomUUID();
        ScanRun runForOtherTarget = new ScanRun(runId, otherTargetId, "MANUAL", null, Instant.now(), Instant.now(), "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(runForOtherTarget));

        assertThatThrownBy(() -> controller.diff(targetId, runId, "previous", principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void diff_runNotCompletedYet_badRequest() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        ScanRun incompleteRun = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(incompleteRun));

        assertThatThrownBy(() -> controller.diff(targetId, runId, "previous", principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void diff_againstPrevious_noEarlierCompletedRun_baselineIsNull_everythingOpenReportsAsNew() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        Instant completedAt = Instant.now();
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), completedAt, "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        when(scanRunRepository.findPreviousCompleted(targetId, completedAt)).thenReturn(Optional.empty());
        Finding f = finding();
        when(findingRepository.findOpenAsOf(targetId, completedAt)).thenReturn(List.of(f));

        FindingDiffResponse response = controller.diff(targetId, runId, "previous", principal);

        assertThat(response.baselineRunId()).isNull();
        assertThat(response.newFindings()).hasSize(1);
        assertThat(response.resolvedFindings()).isEmpty();
    }

    @Test
    void diff_malformedAgainstParameter_notPreviousNotAUuid_badRequest() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), Instant.now(), "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));

        assertThatThrownBy(() -> controller.diff(targetId, runId, "not-a-uuid-and-not-previous", principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void diff_explicitBaselineRunId_notCompleted_badRequest() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        ScanRun compareRun = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), Instant.now(), "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(compareRun));

        UUID baselineId = UUID.randomUUID();
        ScanRun incompleteBaseline = new ScanRun(baselineId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(baselineId)).thenReturn(Optional.of(incompleteBaseline));

        assertThatThrownBy(() -> controller.diff(targetId, runId, baselineId.toString(), principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void diff_explicitValidBaselineRunId_computesDiffAgainstIt() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        Instant compareCompletedAt = Instant.now();
        ScanRun compareRun = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), compareCompletedAt, "COMPLETE");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(compareRun));

        UUID baselineId = UUID.randomUUID();
        Instant baselineCompletedAt = compareCompletedAt.minusSeconds(3600);
        ScanRun baselineRun = new ScanRun(baselineId, targetId, "MANUAL", null, Instant.now(), baselineCompletedAt, "COMPLETE");
        when(scanRunRepository.findById(baselineId)).thenReturn(Optional.of(baselineRun));

        when(findingRepository.findOpenAsOf(targetId, baselineCompletedAt)).thenReturn(List.of());
        when(findingRepository.findOpenAsOf(targetId, compareCompletedAt)).thenReturn(List.of());

        FindingDiffResponse response = controller.diff(targetId, runId, baselineId.toString(), principal);

        assertThat(response.baselineRunId()).isEqualTo(baselineId);
        assertThat(response.compareRunId()).isEqualTo(runId);
    }

    private Finding finding() {
        return new Finding(
                UUID.randomUUID(), "bh-test-1", UUID.randomUUID(), targetId, "HTTP", "RULE_X", "HIGH", "EXPOSURE", "title", "desc",
                null, "asset", UUID.randomUUID(), "OPEN", null, Instant.now(), Instant.now());
    }
}
