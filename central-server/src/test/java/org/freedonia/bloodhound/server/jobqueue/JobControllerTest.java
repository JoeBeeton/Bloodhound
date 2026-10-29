package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.integrations.github.GithubSecretSearchIntegrationRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

/** Covers only the new worker-facing GITHUB_SECRET_SEARCH token lookup - see its own javadoc on JobController for why this is the one worker-to-central-server mid-job call in this codebase. */
class JobControllerTest {

    private final JobClaimService jobClaimService = mock(JobClaimService.class);
    private final JobLifecycleService jobLifecycleService = mock(JobLifecycleService.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final GithubSecretSearchIntegrationRepository githubRepository =
            mock(GithubSecretSearchIntegrationRepository.class);
    private final JobController controller = new JobController(
            jobClaimService, jobLifecycleService, targetRepository, new ObjectMapper(), githubRepository);

    private final UUID targetId = UUID.randomUUID();
    private final UUID orgId = UUID.randomUUID();

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void githubSecretSearchToken_configuredAndEnabled_returnsTheDecryptedToken() {
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target()));
        when(githubRepository.findDecryptedTokenForOrganization(orgId)).thenReturn(Optional.of("ghp_realtoken"));

        ResponseEntity<JobController.GithubTokenResponse> response = controller.githubSecretSearchToken(targetId);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().token()).isEqualTo("ghp_realtoken");
    }

    @Test
    void githubSecretSearchToken_notConfigured_returns204() {
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target()));
        when(githubRepository.findDecryptedTokenForOrganization(orgId)).thenReturn(Optional.empty());

        assertThat(controller.githubSecretSearchToken(targetId).getStatusCode().value()).isEqualTo(204);
    }

    @Test
    void githubSecretSearchToken_unknownTarget_returns204_neverCallsTheIntegrationLookup() {
        when(targetRepository.findById(targetId)).thenReturn(Optional.empty());

        ResponseEntity<JobController.GithubTokenResponse> response = controller.githubSecretSearchToken(targetId);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        org.mockito.Mockito.verifyNoInteractions(githubRepository);
    }
}
