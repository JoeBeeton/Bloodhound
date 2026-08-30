package org.freedonia.bloodhound.server.typosquat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class TyposquatControllerTest {

    private final TyposquatCandidateRepository repository = mock(TyposquatCandidateRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final TyposquatController controller = new TyposquatController(repository, targetRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID candidateId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "v@example.com");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void screenshot_targetNotInCallersOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.screenshot(targetId, candidateId, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void screenshot_candidateHasNoScreenshot_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(repository.findScreenshotPng(targetId, candidateId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.screenshot(targetId, candidateId, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void screenshot_found_returnsPngBytesWithImageContentType() {
        byte[] png = new byte[] {1, 2, 3};
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(repository.findScreenshotPng(targetId, candidateId)).thenReturn(Optional.of(png));

        ResponseEntity<byte[]> response = controller.screenshot(targetId, candidateId, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.IMAGE_PNG);
        assertThat(response.getBody()).isEqualTo(png);
    }

    @Test
    void list_targetNotInCallersOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.list(targetId, principal)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_carriesWhetherTheRealDomainHasAHomepageScreenshot() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(repository.findRegisteredByTarget(targetId)).thenReturn(java.util.List.of());
        when(targetRepository.hasHomepageScreenshot(targetId)).thenReturn(true);

        var response = controller.list(targetId, principal);

        assertThat(response.realDomainHasScreenshot()).isTrue();
        assertThat(response.candidates()).isEmpty();
    }

    @Test
    void realDomainScreenshot_targetNotInCallersOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.realDomainScreenshot(targetId, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void realDomainScreenshot_noneStored_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(targetRepository.findHomepageScreenshotPng(targetId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.realDomainScreenshot(targetId, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void realDomainScreenshot_found_returnsPngBytesWithImageContentType() {
        byte[] png = new byte[] {4, 5, 6};
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(targetRepository.findHomepageScreenshotPng(targetId)).thenReturn(Optional.of(png));

        ResponseEntity<byte[]> response = controller.realDomainScreenshot(targetId, principal);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.IMAGE_PNG);
        assertThat(response.getBody()).isEqualTo(png);
    }
}
