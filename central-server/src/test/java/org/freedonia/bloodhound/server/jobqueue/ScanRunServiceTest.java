package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceCheckRepository;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceCursorRepository;
import org.freedonia.bloodhound.server.compound.CompoundRiskAnalysisService;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.notification.NotificationService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotService;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * No test coverage existed for ScanRunService/createDeepScan before this - added alongside the
 * BUCKET_BRUTE_FORCE target-scoped dispatch change specifically to lock in the pre-existing
 * per-host fanout behavior (PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN) before touching the
 * method, not just to cover the new module.
 */
class ScanRunServiceTest {

    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScoreSnapshotService scoreSnapshotService = mock(ScoreSnapshotService.class);
    private final CompoundRiskAnalysisService compoundRiskAnalysisService = mock(CompoundRiskAnalysisService.class);
    private final SubdomainRepository subdomainRepository = mock(SubdomainRepository.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final BucketBruteForceCheckRepository bucketBruteForceCheckRepository =
            mock(BucketBruteForceCheckRepository.class);
    private final BucketBruteForceCursorRepository bucketBruteForceCursorRepository =
            mock(BucketBruteForceCursorRepository.class);

    private final ScanRunService service = new ScanRunService(
            scanRunRepository,
            scanJobRepository,
            scoreSnapshotService,
            compoundRiskAnalysisService,
            subdomainRepository,
            objectMapper,
            targetRepository,
            findingRepository,
            notificationService,
            bucketBruteForceCheckRepository,
            bucketBruteForceCursorRepository);

    private final UUID targetId = UUID.randomUUID();
    private final UUID triggeredByUserId = UUID.randomUUID();
    private final UUID runId = UUID.randomUUID();

    private void stub(List<String> subdomains) {
        ScanRun run = new ScanRun(runId, targetId, "MANUAL", triggeredByUserId, Instant.now(), null, "RUNNING");
        when(scanRunRepository.insert(targetId, "MANUAL", triggeredByUserId)).thenReturn(run);
        Target target = new Target(
                targetId, UUID.randomUUID(), "acme.com", "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now());
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target));
        when(subdomainRepository.findHostnamesForFanout(eq(targetId), any(Integer.class))).thenReturn(subdomains);
        when(bucketBruteForceCheckRepository.findRecentlyCheckedKeys(eq(targetId), any(Instant.class)))
                .thenReturn(Set.of());
    }

    @Test
    void hostFanoutModules_dispatchOncePerHost_rootPlusEverySubdomain() {
        stub(List.of("api.acme.com", "www.acme.com"));

        service.createDeepScan(targetId, triggeredByUserId);

        // 3 host-fanout module types x 3 hosts (root + 2 subdomains) = 9 jobs.
        for (String moduleType : List.of("PORT_SCAN_DEEP", "ZAP_ACTIVE_SCAN", "NUCLEI_SCAN")) {
            verify(scanJobRepository, times(3)).insert(eq(runId), eq(targetId), eq(moduleType), any(String.class));
        }
    }

    @Test
    void deepScan_alsoDispatchesEveryTier1Job_notJustTier2() {
        // A product review found "Deep scan" was previously Tier-2-only, silently skipping the
        // regular Tier 1 checks (DNS posture, headers, TLS, WHOIS, breach correlation, etc.)
        // entirely - "deep" should mean "everything a regular scan does, plus more," never less.
        stub(List.of("api.acme.com"));

        service.createDeepScan(targetId, triggeredByUserId);

        for (String moduleType : List.of(
                "DNS_POSTURE",
                "HTTP_HEADERS",
                "TLS_ANALYSIS",
                "SUBDOMAIN_ENUM",
                "EXPOSURE_CHECKS",
                "PORT_SCAN_LIGHT",
                "WHOIS",
                "TECH_FINGERPRINT",
                "TYPOSQUAT_MONITOR",
                "BREACH_CORRELATION",
                "DOCUMENT_METADATA")) {
            verify(scanJobRepository, times(1)).insert(eq(runId), eq(targetId), eq(moduleType), any(String.class));
        }
    }

    @Test
    void bucketBruteForce_dispatchesExactlyOnce_regardlessOfSubdomainCount() {
        stub(List.of("api.acme.com", "www.acme.com", "shop.acme.com"));

        service.createDeepScan(targetId, triggeredByUserId);

        // Not fanned out per host, unlike PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN above -
        // exactly one job no matter how many known subdomains this target has.
        verify(scanJobRepository, times(1)).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), any(String.class));
    }

    @Test
    void bucketBruteForce_withNoSubdomainsKnownYet_stillDispatchesOnce() {
        stub(List.of());

        service.createDeepScan(targetId, triggeredByUserId);

        verify(scanJobRepository, times(1)).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), any(String.class));
        for (String moduleType : List.of("PORT_SCAN_DEEP", "ZAP_ACTIVE_SCAN", "NUCLEI_SCAN")) {
            verify(scanJobRepository, times(1)).insert(eq(runId), eq(targetId), eq(moduleType), any(String.class));
        }
    }

    @Test
    void bucketBruteForcePayload_carriesRecentlyCheckedExclusionKeys() {
        stub(List.of());
        when(bucketBruteForceCheckRepository.findRecentlyCheckedKeys(eq(targetId), any(Instant.class)))
                .thenReturn(Set.of("acme-backup|AWS_S3"));

        service.createDeepScan(targetId, triggeredByUserId);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(scanJobRepository).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), payloadCaptor.capture());
        assertThat(payloadCaptor.getValue()).contains("acme-backup|AWS_S3");
    }

    @Test
    void bucketBruteForcePayload_withNothingRecentlyChecked_carriesEmptyExclusionList() {
        stub(List.of());

        service.createDeepScan(targetId, triggeredByUserId);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(scanJobRepository).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), payloadCaptor.capture());
        assertThat(payloadCaptor.getValue()).contains("\"excludeKeys\":[]");
    }

    @Test
    void bucketBruteForcePayload_carriesCurrentLargeWordlistCursorPosition() {
        stub(List.of());
        when(bucketBruteForceCursorRepository.currentPosition(targetId)).thenReturn(4350);

        service.createDeepScan(targetId, triggeredByUserId);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(scanJobRepository).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), payloadCaptor.capture());
        assertThat(payloadCaptor.getValue())
                .contains("\"largeWordlistOffset\":4350")
                .contains("\"largeWordlistBatchSize\":150");
    }

    @Test
    void bucketBruteForcePayload_noCursorRowYet_startsFromZero() {
        stub(List.of());
        // No stubbing of currentPosition - Mockito's default int return is 0, matching
        // BucketBruteForceCursorRepository's own documented "no row yet -> position 0" contract.

        service.createDeepScan(targetId, triggeredByUserId);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(scanJobRepository).insert(eq(runId), eq(targetId), eq("BUCKET_BRUTE_FORCE"), payloadCaptor.capture());
        assertThat(payloadCaptor.getValue()).contains("\"largeWordlistOffset\":0");
    }
}
