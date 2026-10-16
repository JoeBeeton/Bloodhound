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
    void unreachableJob_countsAsTerminal_notFactoredIntoRemainingEstimate() {
        // A confirmed-dead host (see HostUnreachableException) is terminal just like
        // COMPLETE/FAILED/CANCELLED - without this, an UNREACHABLE job would never count as
        // "completed" and would keep contributing a fabricated remaining-time estimate to a
        // scan run that has actually already finished.
        List<JobProgress> jobs = List.of(
                new JobProgress("NUCLEI_SCAN", "COMPLETE", now.minusSeconds(60)),
                new JobProgress("PORT_SCAN_DEEP", "UNREACHABLE", now.minusSeconds(30)));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("NUCLEI_SCAN", 10.0, "PORT_SCAN_DEEP", 5.0), now);

        assertThat(estimate.completedJobs()).isEqualTo(2);
        assertThat(estimate.totalJobs()).isEqualTo(2);
        assertThat(estimate.etaSeconds()).isNull();
    }

    @Test
    void emptyJobList_zeroTotalAndCompleted_nullEta() {
        Estimate estimate = ScanEtaEstimator.estimate(List.of(), Map.of(), now);

        assertThat(estimate.totalJobs()).isZero();
        assertThat(estimate.completedJobs()).isZero();
        assertThat(estimate.etaSeconds()).isNull();
    }

    /**
     * The exact real-world case that motivated this fix: two targets' scan_runs each have their
     * own ZAP_ACTIVE_SCAN jobs queued, but only one ZAP scan runs system-wide at a time. The old
     * max-based model reported "~1 job's own average" (minutes); the real wait is the whole
     * shared queue draining (hours). See ScanEtaEstimator's own javadoc.
     */
    @Test
    void cappedModuleType_usesSystemWideQueueDrainTime_notJustThisRunsOwnJobCount() {
        List<JobProgress> jobs = List.of(
                new JobProgress("ZAP_ACTIVE_SCAN", "CLAIMED", now.minus(60, ChronoUnit.SECONDS)),
                new JobProgress("ZAP_ACTIVE_SCAN", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(
                jobs,
                Map.of("ZAP_ACTIVE_SCAN", 720.0), // 12-minute average, matching the real observed case
                Map.of("ZAP_ACTIVE_SCAN", 26), // 26 remaining system-wide (this run's own 2 included)
                Map.of("ZAP_ACTIVE_SCAN", 1), // one global slot
                now);

        // 26 jobs * 720s / 1 slot = 18,720s (~5.2 hours) - the whole shared queue draining, not
        // this run's own 2 jobs' naive max (~660s, the CLAIMED one's remaining time).
        assertThat(estimate.etaSeconds()).isEqualTo(26 * 720L);
    }

    @Test
    void cappedModuleType_thisRunHasNoneRemaining_notFactoredIntoEta() {
        List<JobProgress> jobs = List.of(new JobProgress("ZAP_ACTIVE_SCAN", "COMPLETE", now.minusSeconds(60)));

        Estimate estimate = ScanEtaEstimator.estimate(
                jobs, Map.of("ZAP_ACTIVE_SCAN", 720.0), Map.of("ZAP_ACTIVE_SCAN", 50), Map.of("ZAP_ACTIVE_SCAN", 1), now);

        // This run's own ZAP job is already COMPLETE - the other 50 system-wide belong to other
        // targets' scan_runs and must not inflate THIS run's own ETA.
        assertThat(estimate.etaSeconds()).isNull();
    }

    @Test
    void cappedModuleType_combinesWithUncappedModuleTypes_viaMax() {
        List<JobProgress> jobs = List.of(
                new JobProgress("ZAP_ACTIVE_SCAN", "PENDING", null),
                new JobProgress("NUCLEI_SCAN", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(
                jobs,
                Map.of("ZAP_ACTIVE_SCAN", 100.0, "NUCLEI_SCAN", 99999.0),
                Map.of("ZAP_ACTIVE_SCAN", 1),
                Map.of("ZAP_ACTIVE_SCAN", 1),
                now);

        // ZAP's own queue-drain (1 * 100 / 1 = 100) loses to NUCLEI_SCAN's uncapped max (99999) -
        // different module types still combine via max, only a capped type's own internal model changes.
        assertThat(estimate.etaSeconds()).isEqualTo(99999L);
    }

    @Test
    void cappedModuleTypeWithNoHistoricalAverage_contributesNothing() {
        List<JobProgress> jobs = List.of(new JobProgress("ZAP_ACTIVE_SCAN", "PENDING", null));

        Estimate estimate =
                ScanEtaEstimator.estimate(jobs, Map.of(), Map.of("ZAP_ACTIVE_SCAN", 10), Map.of("ZAP_ACTIVE_SCAN", 1), now);

        assertThat(estimate.etaSeconds()).isNull();
    }

    @Test
    void threeArgOverload_behavesAsThoughNoModuleTypeIsCapped() {
        // The pre-existing 3-arg form (still used by one test above) must keep behaving exactly
        // as before - this is the delegating overload's own contract, not just happenstance.
        List<JobProgress> jobs = List.of(
                new JobProgress("ZAP_ACTIVE_SCAN", "CLAIMED", now.minus(10, ChronoUnit.SECONDS)),
                new JobProgress("ZAP_ACTIVE_SCAN", "PENDING", null));

        Estimate estimate = ScanEtaEstimator.estimate(jobs, Map.of("ZAP_ACTIVE_SCAN", 20.0), now);

        // Plain max-based model: claimed job has 10s remaining, pending job has the full 20s -
        // max is 20, not a system-wide queue-drain calculation.
        assertThat(estimate.etaSeconds()).isEqualTo(20L);
    }
}
