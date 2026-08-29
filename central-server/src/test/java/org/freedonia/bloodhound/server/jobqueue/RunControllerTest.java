package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class RunControllerTest {

    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanJobAttemptRepository scanJobAttemptRepository = mock(ScanJobAttemptRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final RunController controller =
            new RunController(scanRunRepository, scanJobRepository, scanJobAttemptRepository, targetRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID runId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    @Test
    void get_runNotFound_notFound() {
        when(scanRunRepository.findById(runId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(runId, principal)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_runsTargetInAnotherOrg_notFound_regardlessThatRunItselfExists() {
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(runId, principal)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_ownedRun_assemblesJobsAndTheirAttemptHistory() {
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        Target target = new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now());
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target));

        UUID jobId = UUID.randomUUID();
        ScanJob job = new ScanJob(
                jobId, runId, targetId, "HTTP_HEADERS", "COMPLETE", (short) 0, Instant.now(), "worker-1",
                Instant.now(), Instant.now(), 1, 3, "{\"host\":\"sub.example.com\"}", null, null, Instant.now());
        when(scanJobRepository.findByScanRunId(runId)).thenReturn(List.of(job));

        ScanJobAttempt attempt =
                new ScanJobAttempt(UUID.randomUUID(), jobId, 1, "worker-1", Instant.now(), Instant.now(), "SUCCESS", null, null);
        when(scanJobAttemptRepository.findByScanJobId(jobId)).thenReturn(List.of(attempt));

        ScanRunDetail detail = controller.get(runId, principal);

        assertThat(detail.id()).isEqualTo(runId);
        assertThat(detail.targetHostname()).isEqualTo("example.com");
        assertThat(detail.jobs()).hasSize(1);
        ScanRunDetail.ScanJobStatus jobStatus = detail.jobs().get(0);
        assertThat(jobStatus.moduleType()).isEqualTo("HTTP_HEADERS");
        assertThat(jobStatus.host()).isEqualTo("sub.example.com");
        assertThat(jobStatus.attempts()).hasSize(1);
        assertThat(jobStatus.attempts().get(0).outcome()).isEqualTo("SUCCESS");
    }

    @Test
    void get_jobPayloadWithoutHostKey_hostIsNull() {
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", null, Instant.now(), null, "RUNNING");
        when(scanRunRepository.findById(runId)).thenReturn(Optional.of(run));
        Target target = new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now());
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target));

        UUID jobId = UUID.randomUUID();
        ScanJob job = new ScanJob(
                jobId, runId, targetId, "CT_CHECK", "COMPLETE", (short) 0, Instant.now(), null,
                null, null, 1, 3, "{}", null, null, Instant.now());
        when(scanJobRepository.findByScanRunId(runId)).thenReturn(List.of(job));
        when(scanJobAttemptRepository.findByScanJobId(jobId)).thenReturn(List.of());

        ScanRunDetail detail = controller.get(runId, principal);

        assertThat(detail.jobs().get(0).host()).isNull();
    }
}
