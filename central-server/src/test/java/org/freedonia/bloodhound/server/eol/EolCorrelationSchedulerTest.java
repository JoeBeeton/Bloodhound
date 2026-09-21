package org.freedonia.bloodhound.server.eol;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.findings.ResultIngestionService;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.junit.jupiter.api.Test;

/**
 * Mostly exercises {@link EolCorrelationScheduler#toFindings} - pure finding-synthesis
 * logic, no repository/network interaction. The synthesizeFindings tests at the bottom
 * cover the fetched-at-watermark gate that stops a standing EOL match from re-triggering
 * a scan_run/notification on every tick forever - the same bug class
 * VulnerabilityCorrelationScheduler already hit once for real (see its own javadoc).
 */
class EolCorrelationSchedulerTest {

    private final EndOfLifeClient endOfLifeClient = mock(EndOfLifeClient.class);
    private final EolReleaseCacheRepository cacheRepository = mock(EolReleaseCacheRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ResultIngestionService resultIngestionService = mock(ResultIngestionService.class);

    private final EolCorrelationScheduler scheduler = new EolCorrelationScheduler(
            endOfLifeClient, cacheRepository, scanRunRepository, scanJobRepository, scanRunService, resultIngestionService);

    private static final UUID TARGET_ID = UUID.randomUUID();

    @Test
    void eolRelease_producesTechEolSoftwareDetectedFinding() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.29.5");
        EolRelease release = new EolRelease("1.29", true, LocalDate.now().minusDays(30), false, "1.29.8");

        List<FindingPayload> findings = scheduler.toFindings(candidate, release);

        assertThat(findings).hasSize(1);
        FindingPayload finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("TECH_EOL_SOFTWARE_DETECTED");
        assertThat(finding.severity()).isEqualTo("MEDIUM");
        assertThat(finding.affectedAsset()).isEqualTo("example.com");
        assertThat(finding.evidence())
                .containsEntry("technology", "nginx")
                .containsEntry("version", "1.29.5")
                .containsEntry("releaseCycle", "1.29")
                .containsEntry("daysPastEol", 30L);
    }

    @Test
    void releaseEolWithin90Days_producesTechEolApproachingFinding() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "PHP", "8.1.0");
        EolRelease release = new EolRelease("8.1", false, LocalDate.now().plusDays(45), true, "8.1.30");

        List<FindingPayload> findings = scheduler.toFindings(candidate, release);

        assertThat(findings).hasSize(1);
        FindingPayload finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("TECH_EOL_APPROACHING");
        assertThat(finding.severity()).isEqualTo("LOW");
        assertThat(finding.evidence()).containsEntry("daysUntilEol", 45L);
    }

    @Test
    void releaseEolMoreThan90DaysAway_noFinding() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "PHP", "8.1.0");
        EolRelease release = new EolRelease("8.1", false, LocalDate.now().plusDays(200), true, "8.1.30");
        assertThat(scheduler.toFindings(candidate, release)).isEmpty();
    }

    @Test
    void maintainedReleaseWithNoScheduledEol_noFinding() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.31.6");
        EolRelease release = new EolRelease("1.31", false, null, true, "1.31.6");
        assertThat(scheduler.toFindings(candidate, release)).isEmpty();
    }

    private static ScanRun stubRun(UUID targetId) {
        return new ScanRun(UUID.randomUUID(), targetId, "EOL_CORRELATION", null, Instant.now(), null, "COMPLETE");
    }

    @Test
    void firstEverMatchForATarget_noPriorEolCorrelationRun_synthesizesAndCreatesAScanRun() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.29.5");
        EolRelease release = new EolRelease("1.29", true, LocalDate.now().minusDays(10), false, "1.29.8");
        when(cacheRepository.findEolCandidates(any())).thenReturn(List.of(candidate));
        when(cacheRepository.findAllReleases()).thenReturn(Map.of("nginx", List.of(release)));
        when(cacheRepository.fetchedAtByProduct()).thenReturn(Map.of("nginx", Instant.now()));
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "EOL_CORRELATION")).thenReturn(Optional.empty());
        when(scanRunRepository.insert(eq(TARGET_ID), anyString(), any())).thenReturn(stubRun(TARGET_ID));

        scheduler.synthesizeFindings();

        verify(scanRunRepository).insert(eq(TARGET_ID), eq("EOL_CORRELATION"), any());
        verify(resultIngestionService).ingest(any(), eq(TARGET_ID), eq("EOL_CORRELATION"), any(), any());
    }

    @Test
    void matchUnchangedSinceLastEolCorrelationRun_skipped_noNewScanRunOrNotification() {
        // The exact bug this test locks in: a standing EOL match whose relevant product
        // fetch is no newer than the last synthesis must NOT create another scan_run -
        // that's what spammed a "scan completed" notification every tick forever in the
        // CVE-correlation scheduler before its own watermark fix.
        Instant lastRunAt = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant fetchedAt = lastRunAt.minus(10, ChronoUnit.MINUTES); // older than the last run
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.29.5");
        EolRelease release = new EolRelease("1.29", true, LocalDate.now().minusDays(10), false, "1.29.8");
        when(cacheRepository.findEolCandidates(any())).thenReturn(List.of(candidate));
        when(cacheRepository.findAllReleases()).thenReturn(Map.of("nginx", List.of(release)));
        when(cacheRepository.fetchedAtByProduct()).thenReturn(Map.of("nginx", fetchedAt));
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "EOL_CORRELATION")).thenReturn(Optional.of(lastRunAt));

        scheduler.synthesizeFindings();

        verify(scanRunRepository, never()).insert(eq(TARGET_ID), anyString(), any());
        verify(resultIngestionService, never()).ingest(any(), eq(TARGET_ID), anyString(), any(), any());
    }

    @Test
    void productRefetchedSinceLastRun_synthesizesAgain() {
        Instant lastRunAt = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant fetchedAt = Instant.now(); // a real refresh landed something new since last run
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.29.5");
        EolRelease release = new EolRelease("1.29", true, LocalDate.now().minusDays(10), false, "1.29.8");
        when(cacheRepository.findEolCandidates(any())).thenReturn(List.of(candidate));
        when(cacheRepository.findAllReleases()).thenReturn(Map.of("nginx", List.of(release)));
        when(cacheRepository.fetchedAtByProduct()).thenReturn(Map.of("nginx", fetchedAt));
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "EOL_CORRELATION")).thenReturn(Optional.of(lastRunAt));
        when(scanRunRepository.insert(eq(TARGET_ID), anyString(), any())).thenReturn(stubRun(TARGET_ID));

        scheduler.synthesizeFindings();

        verify(scanRunRepository).insert(eq(TARGET_ID), eq("EOL_CORRELATION"), any());
    }

    @Test
    void candidateWithNoCachedReleasesYet_skipped_noCrash() {
        EolCandidate candidate = new EolCandidate(TARGET_ID, "example.com", "nginx", "1.29.5");
        when(cacheRepository.findEolCandidates(any())).thenReturn(List.of(candidate));
        when(cacheRepository.findAllReleases()).thenReturn(Map.of());
        when(cacheRepository.fetchedAtByProduct()).thenReturn(Map.of());

        scheduler.synthesizeFindings();

        verify(scanRunRepository, never()).insert(any(), any(), any());
    }

    @Test
    void noCandidatesAtAll_returnsEarly_neverQueriesFurther() {
        when(cacheRepository.findEolCandidates(any())).thenReturn(List.of());

        scheduler.synthesizeFindings();

        verify(cacheRepository, never()).findAllReleases();
    }
}
