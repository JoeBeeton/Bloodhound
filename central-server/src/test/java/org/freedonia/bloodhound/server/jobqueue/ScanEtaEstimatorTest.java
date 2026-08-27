package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.Estimate;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.JobProgress;
import org.junit.jupiter.api.Test;

class ScanEtaEstimatorTest {

    private final Instant now = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void allJobsTerminal_zeroEta_fullyCompleted() {
        List<JobProgress> jobs = List.of(
                new JobProgress("HTTP_HEADERS", "COMPLETE", now.minusSeconds(60)),
                new JobProgress("TLS", "FAILED", now.minusSeconds(30)));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("HTTP_HEADERS", 10.0, "TLS", 5.0), now);

        assertThat(estimate.completedJobs()).isEqualTo(2);
        assertThat(estimate.totalJobs()).isEqualTo(2);
        assertThat(estimate.etaSeconds()).isNull();
    }

    @Test
    void pendingJob_noClaimedAt_usesFullHistoricalAverage() {
        List<JobProgress> jobs = List.of(new JobProgress("DNS_POSTURE", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("DNS_POSTURE", 42.0), now);

        assertThat(estimate.etaSeconds()).isEqualTo(42L);
        assertThat(estimate.completedJobs()).isZero();
    }

    @Test
    void runningJob_subtractsElapsedTimeFromAverage() {
        List<JobProgress> jobs = List.of(new JobProgress("SUBDOMAIN_ENUM", "RUNNING", now.minus(20, ChronoUnit.SECONDS)));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("SUBDOMAIN_ENUM", 50.0), now);

        assertThat(estimate.etaSeconds()).isEqualTo(30L);
    }

    @Test
    void runningJob_alreadyPastHistoricalAverage_flooredAtZero_notNegative() {
        List<JobProgress> jobs = List.of(new JobProgress("SUBDOMAIN_ENUM", "RUNNING", now.minus(500, ChronoUnit.SECONDS)));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("SUBDOMAIN_ENUM", 50.0), now);

        assertThat(estimate.etaSeconds()).isEqualTo(0L);
    }

    @Test
    void multipleIncompleteJobs_etaIsTheMaxRemaining_notSum() {
        List<JobProgress> jobs = List.of(
                new JobProgress("A", "RUNNING", now.minus(10, ChronoUnit.SECONDS)),
                new JobProgress("B", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("A", 20.0, "B", 100.0), now);

        // A: 20-10=10 remaining. B: 100 remaining (not started). Max is 100, not 110 - jobs run
        // concurrently across workers, not sequentially.
        assertThat(estimate.etaSeconds()).isEqualTo(100L);
    }

    @Test
    void moduleTypeWithNoHistoricalData_contributesNothing_notFabricatedGuess() {
        List<JobProgress> jobs = List.of(new JobProgress("BRAND_NEW_MODULE", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of(), now);

        assertThat(estimate.etaSeconds()).isNull();
    }

    @Test
    void emptyJobList_zeroTotalAndCompleted_nullEta() {
        Estimate estimate = ScanEtaEstimator.estimate(List.of(), Map.of(), now);

        assertThat(estimate.totalJobs()).isZero();
        assertThat(estimate.completedJobs()).isZero();
        assertThat(estimate.etaSeconds()).isNull();
    }
}
