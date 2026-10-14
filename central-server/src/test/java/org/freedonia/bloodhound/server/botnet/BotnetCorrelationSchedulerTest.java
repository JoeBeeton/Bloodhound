package org.freedonia.bloodhound.server.botnet;

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
 * Mostly exercises {@link BotnetCorrelationScheduler#toFinding} (pure) and the
 * fetched-at-watermark gate - the same bug class VulnerabilityCorrelationScheduler already hit
 * once for real (see its own javadoc): a standing match must not create a new scan_run/notification
 * on every tick forever.
 */
class BotnetCorrelationSchedulerTest {

    private final FeodoTrackerClient client = mock(FeodoTrackerClient.class);
    private final BotnetIpCacheRepository cacheRepository = mock(BotnetIpCacheRepository.class);
    private final TargetIpRepository targetIpRepository = mock(TargetIpRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ResultIngestionService resultIngestionService = mock(ResultIngestionService.class);

    private final BotnetCorrelationScheduler scheduler = new BotnetCorrelationScheduler(
            client, cacheRepository, targetIpRepository, scanRunRepository, scanJobRepository, scanRunService,
            resultIngestionService);

    private static final UUID TARGET_ID = UUID.randomUUID();

    @Test
    void matchedIp_producesNetworkKnownBotnetC2Finding() {
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        BotnetIpEntry match = new BotnetIpEntry("1.2.3.4", "QakBot", LocalDate.of(2025, 12, 30));

        FindingPayload finding = scheduler.toFinding(candidate, match);

        assertThat(finding.ruleId()).isEqualTo("NETWORK_IP_KNOWN_BOTNET_C2");
        assertThat(finding.severity()).isEqualTo("CRITICAL");
        assertThat(finding.affectedAsset()).isEqualTo("app.example.com");
        assertThat(finding.evidence())
                .containsEntry("ipAddress", "1.2.3.4")
                .containsEntry("malware", "QakBot")
                .containsEntry("firstSeenAsC2", "2025-12-30")
                .containsEntry("source", "abuse.ch Feodo Tracker");
    }

    @Test
    void matchWithNoFirstSeenDate_omitsThatEvidenceKeyRatherThanNull() {
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        BotnetIpEntry match = new BotnetIpEntry("1.2.3.4", "QakBot", null);

        FindingPayload finding = scheduler.toFinding(candidate, match);

        assertThat(finding.evidence()).doesNotContainKey("firstSeenAsC2");
    }

    private static ScanRun stubRun(UUID targetId) {
        return new ScanRun(UUID.randomUUID(), targetId, "BOTNET_CORRELATION", null, Instant.now(), null, "COMPLETE");
    }

    @Test
    void firstEverMatchForATarget_noPriorBotnetCorrelationRun_synthesizesAndCreatesAScanRun() {
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        BotnetIpEntry match = new BotnetIpEntry("1.2.3.4", "QakBot", LocalDate.now());
        when(targetIpRepository.findAllActiveTargetIps()).thenReturn(List.of(candidate));
        when(cacheRepository.findMatching(any())).thenReturn(Map.of("1.2.3.4", match));
        when(cacheRepository.fetchedAt()).thenReturn(Instant.now());
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "BOTNET_CORRELATION")).thenReturn(Optional.empty());
        when(scanRunRepository.insert(eq(TARGET_ID), anyString(), any())).thenReturn(stubRun(TARGET_ID));

        scheduler.synthesizeFindings();

        verify(scanRunRepository).insert(eq(TARGET_ID), eq("BOTNET_CORRELATION"), any());
        verify(resultIngestionService).ingest(any(), eq(TARGET_ID), eq("BOTNET_CORRELATION"), any(), any());
    }

    @Test
    void matchUnchangedSinceLastBotnetCorrelationRun_skipped_noNewScanRunOrNotification() {
        Instant lastRunAt = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant fetchedAt = lastRunAt.minus(10, ChronoUnit.MINUTES); // older than the last run
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        BotnetIpEntry match = new BotnetIpEntry("1.2.3.4", "QakBot", LocalDate.now());
        when(targetIpRepository.findAllActiveTargetIps()).thenReturn(List.of(candidate));
        when(cacheRepository.findMatching(any())).thenReturn(Map.of("1.2.3.4", match));
        when(cacheRepository.fetchedAt()).thenReturn(fetchedAt);
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "BOTNET_CORRELATION")).thenReturn(Optional.of(lastRunAt));

        scheduler.synthesizeFindings();

        verify(scanRunRepository, never()).insert(eq(TARGET_ID), anyString(), any());
        verify(resultIngestionService, never()).ingest(any(), eq(TARGET_ID), anyString(), any(), any());
    }

    @Test
    void feedRefreshedSinceLastRun_synthesizesAgain() {
        Instant lastRunAt = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant fetchedAt = Instant.now(); // a real refresh landed something new since last run
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        BotnetIpEntry match = new BotnetIpEntry("1.2.3.4", "QakBot", LocalDate.now());
        when(targetIpRepository.findAllActiveTargetIps()).thenReturn(List.of(candidate));
        when(cacheRepository.findMatching(any())).thenReturn(Map.of("1.2.3.4", match));
        when(cacheRepository.fetchedAt()).thenReturn(fetchedAt);
        when(scanRunRepository.findLastStartedAt(TARGET_ID, "BOTNET_CORRELATION")).thenReturn(Optional.of(lastRunAt));
        when(scanRunRepository.insert(eq(TARGET_ID), anyString(), any())).thenReturn(stubRun(TARGET_ID));

        scheduler.synthesizeFindings();

        verify(scanRunRepository).insert(eq(TARGET_ID), eq("BOTNET_CORRELATION"), any());
    }

    @Test
    void noMatchesAtAll_noScanRunCreated() {
        TargetIpRepository.Candidate candidate = new TargetIpRepository.Candidate(TARGET_ID, "app.example.com", "1.2.3.4");
        when(targetIpRepository.findAllActiveTargetIps()).thenReturn(List.of(candidate));
        when(cacheRepository.findMatching(any())).thenReturn(Map.of());

        scheduler.synthesizeFindings();

        verify(scanRunRepository, never()).insert(any(), any(), any());
    }

    @Test
    void noCandidatesAtAll_returnsEarly_neverQueriesCache() {
        when(targetIpRepository.findAllActiveTargetIps()).thenReturn(List.of());

        scheduler.synthesizeFindings();

        verify(cacheRepository, never()).findMatching(any());
    }
}
