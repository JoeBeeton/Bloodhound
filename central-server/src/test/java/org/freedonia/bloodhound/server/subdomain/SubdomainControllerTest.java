package org.freedonia.bloodhound.server.subdomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Map;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class SubdomainControllerTest {

    private final SubdomainRepository subdomainRepository = mock(SubdomainRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final SubdomainController controller =
            new SubdomainController(subdomainRepository, targetRepository, findingRepository);

    {
        when(findingRepository.findWafStatusByTarget(any())).thenReturn(Map.of());
        when(findingRepository.findTlsFindingsByTarget(any())).thenReturn(Map.of());
    }

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Target target() {
        return new Target(targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
    }

    private Subdomain subdomain(String hostname) {
        return new Subdomain(UUID.randomUUID(), targetId, hostname, Instant.now(), Instant.now(), "CRTSH", true, List.of(), null);
    }

    @Test
    void list_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.list(targetId, null, null, 200, 0, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_ownedTarget_returnsTotalCountHeader() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), anyInt()))
                .thenReturn(List.of(subdomain("a.example.com")));
        when(subdomainRepository.countByTarget(targetId, null, null)).thenReturn(57107);

        ResponseEntity<List<SubdomainSummary>> response = controller.list(targetId, null, null, 200, 0, principal);

        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("57107");
    }

    @Test
    void list_limitClampedToMax500() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, null, 100000, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, null, null, 500, 0);
    }

    @Test
    void list_limitClampedToMin1() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, null, 0, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, null, null, 1, 0);
    }

    @Test
    void list_negativeOffset_clampedToZero() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(targetId, null, null, 200, -50, principal);

        verify(subdomainRepository).findByTarget(targetId, null, null, 200, 0);
    }

    @Test
    void list_hostnameFilter_passedThroughToRepository() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), eq("admin"), any(), anyInt(), anyInt()))
                .thenReturn(List.of());
        when(subdomainRepository.countByTarget(targetId, "admin", null)).thenReturn(0);

        controller.list(targetId, "admin", null, 200, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, "admin", null, 200, 0);
        verify(subdomainRepository).countByTarget(targetId, "admin", null);
    }

    @Test
    void list_hasIpFilter_passedThroughToRepository() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), eq(true), anyInt(), anyInt()))
                .thenReturn(List.of());
        when(subdomainRepository.countByTarget(targetId, null, true)).thenReturn(0);

        controller.list(targetId, null, true, 200, 0, principal);

        verify(subdomainRepository).findByTarget(targetId, null, true, 200, 0);
        verify(subdomainRepository).countByTarget(targetId, null, true);
    }

    @Test
    void export_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.export(targetId, null, null, principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void export_ownedTarget_returnsCsvWithContentDisposition() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), eq(0)))
                .thenReturn(List.of(subdomain("a.example.com")));

        ResponseEntity<byte[]> response = controller.export(targetId, null, null, principal);

        assertThat(response.getHeaders().getContentType().toString()).startsWith("text/csv");
        assertThat(response.getHeaders().getFirst("Content-Disposition")).contains("example.com-subdomains-");
        assertThat(new String(response.getBody())).contains("a.example.com,Active,CRTSH");
    }

    @Test
    void export_fetchesFarMoreThanTheListEndpointsMaxLimit() {
        // The point of a separate export endpoint - GET /subdomains is capped at 500 for the
        // paginated UI table, but export must return the target's *entire* subdomain set.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), any(), any(), anyInt(), eq(0))).thenReturn(List.of());

        controller.export(targetId, null, null, principal);

        verify(subdomainRepository)
                .findByTarget(
                        eq(targetId),
                        eq(null),
                        eq(null),
                        org.mockito.ArgumentMatchers.intThat(limit -> limit > 500),
                        eq(0));
    }

    @Test
    void export_hostnameFilter_passedThroughToRepository() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTarget(eq(targetId), eq("admin"), any(), anyInt(), eq(0)))
                .thenReturn(List.of());

        controller.export(targetId, "admin", null, principal);

        verify(subdomainRepository).findByTarget(eq(targetId), eq("admin"), eq(null), anyInt(), eq(0));
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

    @Test
    void add_targetInAnotherOrg_notFound() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.add(
                        targetId, new SubdomainController.AddSubdomainRequest("sub.example.com"), principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void add_outOfScopeHostname_badRequest() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));

        assertThatThrownBy(() -> controller.add(
                        targetId, new SubdomainController.AddSubdomainRequest("evil.com"), principal))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void add_malformedHostname_rejectedBeforeTheScopeCheck() {
        // A security review found this endpoint had no hostname-shape check at all - this exact
        // value's host (per java.net.URI) is "central-server", which SafeAddressValidator's
        // resolve-and-check would wave through as a never-resolving name while inScope's suffix
        // check never even applied, since "example.com" is still a trailing match on the raw
        // string. Rejected here before any of that runs.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));

        assertThatThrownBy(() -> controller.add(
                        targetId,
                        new SubdomainController.AddSubdomainRequest("central-server#.example.com"),
                        principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
        verify(subdomainRepository, never()).upsert(any(), any(), any(), any(), any());
    }

    @Test
    void add_bareRootDomain_isInScope() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTargetAndHostname(targetId, "example.com"))
                .thenReturn(Optional.of(subdomain("example.com")));

        ResponseEntity<SubdomainSummary> response =
                controller.add(targetId, new SubdomainController.AddSubdomainRequest("example.com"), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        verify(subdomainRepository).upsert(targetId, "example.com", "MANUAL", List.of(), null);
    }

    @Test
    void add_inScopeHostname_lowercasedAndTrimmed_upsertsAsManual() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(subdomainRepository.findByTargetAndHostname(targetId, "sub.example.com"))
                .thenReturn(Optional.of(subdomain("sub.example.com")));

        ResponseEntity<SubdomainSummary> response = controller.add(
                targetId, new SubdomainController.AddSubdomainRequest("  SUB.Example.com  "), principal);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody().hostname()).isEqualTo("sub.example.com");
        verify(subdomainRepository).upsert(targetId, "sub.example.com", "MANUAL", List.of(), null);
    }

    private static int anyInt() {
        return org.mockito.ArgumentMatchers.anyInt();
    }
}
