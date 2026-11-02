package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.integrations.github.GithubSecretSearchIntegrationRepository;
import org.freedonia.bloodhound.server.jobqueue.dto.WorkerScopedRequest;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

/** Covers only the worker-facing GITHUB_SECRET_SEARCH token lookup - see its own javadoc on JobController for why this is the one worker-to-central-server mid-job call in this codebase. */
class JobControllerTest {

    private final JobClaimService jobClaimService = mock(JobClaimService.class);
    private final JobLifecycleService jobLifecycleService = mock(JobLifecycleService.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final GithubSecretSearchIntegrationRepository githubRepository =
            mock(GithubSecretSearchIntegrationRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final JobController controller = new JobController(
            jobClaimService, jobLifecycleService, targetRepository, new ObjectMapper(), githubRepository, scanJobRepository);

    private final UUID jobId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID orgId = UUID.randomUUID();
    private final WorkerScopedRequest request = new WorkerScopedRequest("worker-1");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    private ScanJob job(String moduleType) {
        return new ScanJob(
                jobId, UUID.randomUUID(), targetId, moduleType, "RUNNING", (short) 0, Instant.now(), "worker-1",
                Instant.now(), Instant.now(), 1, 3, "{}", null, null, Instant.now());
    }

    @Test
    void heldGithubJob_configuredAndEnabled_returnsTheDecryptedToken() {
        when(scanJobRepository.findByIdOwnedBy(jobId, "worker-1")).thenReturn(Optional.of(job("GITHUB_SECRET_SEARCH")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target()));
        when(githubRepository.findDecryptedTokenForOrganization(orgId)).thenReturn(Optional.of("ghp_realtoken"));

        ResponseEntity<JobController.GithubTokenResponse> response = controller.githubSecretSearchToken(jobId, request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().token()).isEqualTo("ghp_realtoken");
    }

    @Test
    void heldGithubJob_notConfigured_returns204() {
        when(scanJobRepository.findByIdOwnedBy(jobId, "worker-1")).thenReturn(Optional.of(job("GITHUB_SECRET_SEARCH")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target()));
        when(githubRepository.findDecryptedTokenForOrganization(orgId)).thenReturn(Optional.empty());

        assertThat(controller.githubSecretSearchToken(jobId, request).getStatusCode().value()).isEqualTo(204);
    }

    @Test
    void jobNotHeldByThisWorker_404_neverTouchesTheToken() {
        when(scanJobRepository.findByIdOwnedBy(jobId, "worker-1")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.githubSecretSearchToken(jobId, request))
                .isInstanceOfSatisfying(
                        ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(404));
        verifyNoInteractions(githubRepository);
    }

    @Test
    void heldJobOfAnotherModuleType_404_neverTouchesTheToken() {
        when(scanJobRepository.findByIdOwnedBy(jobId, "worker-1")).thenReturn(Optional.of(job("HTTP_HEADERS")));

        assertThatThrownBy(() -> controller.githubSecretSearchToken(jobId, request))
                .isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(githubRepository);
    }
}
