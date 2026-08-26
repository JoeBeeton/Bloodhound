package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.Estimate;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.JobProgress;
import org.junit.jupiter.api.Test;

class ScanEtaEstimatorTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    @Test
    void allTerminal_zeroEta_noRemainingWork() {
        List<JobProgress> jobs = List.of(
                new JobProgress("DNS_POSTURE", "COMPLETE", null), new JobProgress("HTTP_HEADERS", "FAILED", null));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of("DNS_POSTURE", 10.0, "HTTP_HEADERS", 5.0), NOW);
        assertThat(est.completedJobs()).isEqualTo(2);
        assertThat(est.totalJobs()).isEqualTo(2);
        assertThat(est.etaSeconds()).isNull();
    }

    @Test
    void pendingJob_usesFullHistoricalAverage_noClaimTimeToSubtract() {
        List<JobProgress> jobs = List.of(new JobProgress("PORT_SCAN_LIGHT", "PENDING", null));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of("PORT_SCAN_LIGHT", 90.0), NOW);
        assertThat(est.etaSeconds()).isEqualTo(90L);
        assertThat(est.completedJobs()).isZero();
    }

    @Test
    void runningJob_subtractsElapsedTimeSinceClaim() {
        Instant claimedAt = NOW.minusSeconds(30);
        List<JobProgress> jobs = List.of(new JobProgress("HTTP_HEADERS", "RUNNING", claimedAt));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of("HTTP_HEADERS", 50.0), NOW);
        assertThat(est.etaSeconds()).isEqualTo(20L); // 50 - 30 elapsed
    }

    @Test
    void runningJob_alreadyOverHistoricalAverage_clampsToZero_notNegative() {
        Instant claimedAt = NOW.minusSeconds(200);
        List<JobProgress> jobs = List.of(new JobProgress("HTTP_HEADERS", "RUNNING", claimedAt));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of("HTTP_HEADERS", 50.0), NOW);
        assertThat(est.etaSeconds()).isEqualTo(0L);
    }

    @Test
    void overallEta_isMaxOfRemainingEstimates_notSum_becauseJobsRunConcurrently() {
        List<JobProgress> jobs = List.of(
                new JobProgress("HTTP_HEADERS", "PENDING", null), // 5s
                new JobProgress("PORT_SCAN_DEEP", "PENDING", null), // 400s - the real bottleneck
                new JobProgress("DNS_POSTURE", "COMPLETE", null));
        Estimate est = ScanEtaEstimator.estimate(
                jobs, Map.of("HTTP_HEADERS", 5.0, "PORT_SCAN_DEEP", 400.0, "DNS_POSTURE", 3.0), NOW);
        assertThat(est.etaSeconds()).isEqualTo(400L);
        assertThat(est.completedJobs()).isEqualTo(1);
        assertThat(est.totalJobs()).isEqualTo(3);
    }

    @Test
    void moduleWithNoHistoricalData_contributesNoEstimate_ratherThanGuessing() {
        List<JobProgress> jobs = List.of(new JobProgress("BRAND_NEW_MODULE", "RUNNING", NOW.minusSeconds(5)));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of(), NOW);
        assertThat(est.etaSeconds()).isNull();
    }

    @Test
    void mixOfKnownAndUnknownModules_etaReflectsOnlyTheKnownOne() {
        List<JobProgress> jobs = List.of(
                new JobProgress("UNKNOWN_MODULE", "PENDING", null), new JobProgress("HTTP_HEADERS", "PENDING", null));
        Estimate est = ScanEtaEstimator.estimate(jobs, Map.of("HTTP_HEADERS", 12.0), NOW);
        assertThat(est.etaSeconds()).isEqualTo(12L);
    }
}
