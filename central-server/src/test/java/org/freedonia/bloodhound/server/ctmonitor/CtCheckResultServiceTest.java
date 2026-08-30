package org.freedonia.bloodhound.server.ctmonitor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CtCheckResultServiceTest {

    private final SubdomainRepository subdomainRepository = mock(SubdomainRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final CtCheckResultService service =
            new CtCheckResultService(subdomainRepository, scanRunService, scanRunRepository);
    private final UUID targetId = UUID.randomUUID();

    @BeforeEach
    void noRunInFlightByDefault() {
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(false);
    }

    @Test
    void newCertificateBackedHostnameTriggersRescan() {
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));

        service.handle(targetId, Map.of("hostnames", List.of("known.example.com", "brand-new.example.com")));

        verify(scanRunService).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void newHostname_butAScanIsAlreadyRunningForTheTarget_skipsRescan() {
        // Same race ScanAutoScheduler already guards its own cadence-driven scans against - a
        // CT check (every 20 min, plus once on every startup) landing while a manual/scheduled/
        // another CT-triggered scan is already running for this target must not double-enqueue a
        // second full job set.
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));
        when(scanRunRepository.existsRunningForTarget(targetId)).thenReturn(true);

        service.handle(targetId, Map.of("hostnames", List.of("known.example.com", "brand-new.example.com")));

        verify(scanRunService, never()).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void noNewHostname_neverEvenChecksInFlightState() {
        // The in-flight check is a real (if cheap) query - no reason to run it when nothing
        // would trigger a rescan anyway.
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));

        service.handle(targetId, Map.of("hostnames", List.of("known.example.com")));

        verify(scanRunRepository, never()).existsRunningForTarget(targetId);
        verify(scanRunService, never()).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void onlyAlreadyKnownHostnamesDoNotTriggerRescan() {
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of("known.example.com", "also-known.example.com"));

        service.handle(targetId, Map.of("hostnames", List.of("known.example.com", "also-known.example.com")));

        verify(scanRunService, never()).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void emptyDiscoveredListDoesNotTriggerRescan() {
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));

        service.handle(targetId, Map.of("hostnames", List.of()));

        verify(scanRunService, never()).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void missingHostnamesKeyIsTreatedAsEmpty() {
        when(subdomainRepository.findHostnames(targetId)).thenReturn(Set.of());

        service.handle(targetId, Map.of());

        verify(scanRunService, never()).createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    @Test
    void hasGenuinelyNewHostname_pureLogic() {
        assertThat(CtCheckResultService.hasGenuinelyNewHostname(List.of("a", "b"), Set.of("a"))).isTrue();
        assertThat(CtCheckResultService.hasGenuinelyNewHostname(List.of("a"), Set.of("a", "b"))).isFalse();
        assertThat(CtCheckResultService.hasGenuinelyNewHostname(List.of(), Set.of())).isFalse();
    }

    @Test
    void extractHostnames_pureParsing() {
        assertThat(CtCheckResultService.extractHostnames(Map.of("hostnames", List.of("a.example.com", "b.example.com"))))
                .containsExactly("a.example.com", "b.example.com");
        assertThat(CtCheckResultService.extractHostnames(Map.of())).isEmpty();
        assertThat(CtCheckResultService.extractHostnames(null)).isEmpty();
        assertThat(CtCheckResultService.extractHostnames(Map.of("hostnames", "not-a-list"))).isEmpty();
    }
}
