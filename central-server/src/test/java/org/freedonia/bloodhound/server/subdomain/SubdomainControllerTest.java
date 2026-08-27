package org.freedonia.bloodhound.server.subdomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class SubdomainControllerTest {

    private final SubdomainRepository subdomainRepository = mock(SubdomainRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final SubdomainController controller = new SubdomainController(subdomainRepository, targetRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now());
    }

    private Subdomain subdomain(String hostname) {
        return new Subdomain(UUID.randomUUID(), targetId, hostname, Instant.now(), Instant.now(), "CRTSH", true, List.of(), null);
    }

    @Test
    void list_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.list(targetId, null, 200, 0, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_ownedTarget_returnsTotalCountHeader() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), anyInt(), anyInt()))
                .thenReturn(List.of(subdomain("a.example.com")));
        when(subdomainRepository.countByTarget(targetId, null)).thenReturn(57107);

        ResponseEntity<List<SubdomainSummary>> response = controller.list(targetId, null, 200, 0, principal);

        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("57107");
    }

    @Test
    void list_limitClampedToMax500() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, 100000, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, null, 500, 0);
    }

    @Test
    void list_limitClampedToMin1() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, 0, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, null, 1, 0);
    }

    @Test
    void list_negativeOffset_clampedToZero() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, 200, -50, principal);

        verify(subdomainRepository).findByTarget(targetId, null, 200, 0);
    }

    @Test
    void list_hostnameFilter_passedThroughToRepository() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), eq("admin"), anyInt(), anyInt())).thenReturn(List.of());
        when(subdomainRepository.countByTarget(targetId, "admin")).thenReturn(0);

        controller.list(targetId, "admin", 200, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, "admin", 200, 0);
        verify(subdomainRepository).countByTarget(targetId, "admin");
    }

    @Test
    void get_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(targetId, "a.example.com", principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_hostnameNotFoundOnTarget_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTargetAndHostname(targetId, "missing.example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(targetId, "missing.example.com", principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_existingHostname_returnsSummary() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTargetAndHostname(targetId, "a.example.com"))
                .thenReturn(Optional.of(subdomain("a.example.com")));

        SubdomainSummary result = controller.get(targetId, "a.example.com", principal);

        assertThat(result.hostname()).isEqualTo("a.example.com");
    }

    private static int anyInt() {
        return org.mockito.ArgumentMatchers.anyInt();
    }
}
