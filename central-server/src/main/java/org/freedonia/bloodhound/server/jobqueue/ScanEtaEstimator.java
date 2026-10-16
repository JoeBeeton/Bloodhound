package org.freedonia.bloodhound.server.jobqueue;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Estimates how much longer a scan_run has left, from real historical per-module-type
 * average durations (see {@link ScanJobAttemptRepository#averageSecondsByModuleType}).
 * This is a heuristic, not a guarantee: jobs within one scan_run run concurrently across
 * however many workers happen to be free, not strictly sequentially, and general
 * worker-availability/contention still isn't modeled - the ETA for an uncapped module type is
 * "how long the slowest still-incomplete job of that type has historically taken," not an
 * accounting of actual queueing delay against every other org's work sharing the same worker
 * pool. A module with no historical data yet (e.g. brand new to this deployment) contributes no
 * estimate rather than a fabricated guess.
 *
 * <p>One queueing effect IS modeled explicitly, because it was found to make the estimate wrong
 * by an order of magnitude in practice: a module type with a hard, deployment-wide concurrency
 * cap below the worker pool size (currently just ZAP_ACTIVE_SCAN - see
 * {@code ScanJobRepository}'s own javadoc on the shared zap sidecar this protects). The original
 * max-based model treated 26 queued ZAP_ACTIVE_SCAN jobs across two targets as if they could all
 * run at once, reporting "~12 minutes" (one job's own average) when the real wait - only one ZAP
 * scan running system-wide at a time - was actually hours. See the 5-argument overload below.
 */
public final class ScanEtaEstimator {

    private ScanEtaEstimator() {}

    public record JobProgress(String moduleType, String status, Instant claimedAt) {}

    public record Estimate(int completedJobs, int totalJobs, Long etaSeconds) {}

    private static final java.util.Set<String> TERMINAL =
            java.util.Set.of("COMPLETE", "FAILED", "CANCELLED", "UNREACHABLE");

    /** No known concurrency caps - every module type falls back to the plain max-based model. */
    public static Estimate estimate(List<JobProgress> jobs, Map<String, Double> avgSecondsByModuleType, Instant now) {
        return estimate(jobs, avgSecondsByModuleType, Map.of(), Map.of(), now);
    }

    /**
     * @param systemWideRemainingByModuleType how many PENDING/CLAIMED/RUNNING jobs of a
     *     concurrency-capped module type exist across the WHOLE deployment right now, not just
     *     this one scan_run - see {@code ScanJobRepository#countPendingOrInProgress}. Only ever
     *     consulted for module types that also appear in {@code concurrencyCapByModuleType}; an
     *     entry missing here for such a type is treated as "no other competing work" (0), the
     *     same as an empty map.
     * @param concurrencyCapByModuleType how many jobs of that module type can run at once,
     *     system-wide, independent of worker count - see {@code ScanJobRepository#zapMaxConcurrentScans}.
     *     A module type absent from this map is assumed uncapped (falls back to the plain
     *     max-based model, same as the 3-argument overload).
     */
    public static Estimate estimate(
            List<JobProgress> jobs,
            Map<String, Double> avgSecondsByModuleType,
            Map<String, Integer> systemWideRemainingByModuleType,
            Map<String, Integer> concurrencyCapByModuleType,
            Instant now) {
        int completed = (int) jobs.stream().filter(j -> TERMINAL.contains(j.status())).count();

        Map<String, Long> maxRemainingByModuleType = new HashMap<>();
        for (JobProgress job : jobs) {
            if (TERMINAL.contains(job.status()) || concurrencyCapByModuleType.containsKey(job.moduleType())) {
                // Capped types are handled below via the system-wide queue-depth model instead -
                // a per-job remaining-time estimate means nothing for a type that can't run in
                // parallel with itself in the first place.
                continue;
            }
            Double avg = avgSecondsByModuleType.get(job.moduleType());
            if (avg == null) {
                continue; // no historical basis for this module type - contributes nothing, not a guess
            }
            long rounded = Math.round(remainingSecondsFor(job, avg, now));
            maxRemainingByModuleType.merge(job.moduleType(), rounded, Math::max);
        }

        Long maxRemaining = null;
        for (long candidate : maxRemainingByModuleType.values()) {
            if (maxRemaining == null || candidate > maxRemaining) {
                maxRemaining = candidate;
            }
        }

        for (Map.Entry<String, Integer> capEntry : concurrencyCapByModuleType.entrySet()) {
            String moduleType = capEntry.getKey();
            boolean thisRunHasAnyRemaining =
                    jobs.stream().anyMatch(j -> moduleType.equals(j.moduleType()) && !TERMINAL.contains(j.status()));
            if (!thisRunHasAnyRemaining) {
                continue; // this run's own work of this type is already done - not part of its ETA
            }
            Double avg = avgSecondsByModuleType.get(moduleType);
            if (avg == null) {
                continue;
            }
            int cap = Math.max(1, capEntry.getValue());
            int systemWideRemaining = systemWideRemainingByModuleType.getOrDefault(moduleType, 0);
            // Every job of this type competing for the same global slot(s), across every
            // scan_run - this run's own jobs are somewhere in that shared queue, so the time for
            // the WHOLE queue to drain is an honest upper bound for when this run's own last one
            // finishes. Round-robin target fairness (see ScanJobRepository#claim's own ordering)
            // means the typical case lands inside this bound, not right at the end of it - but an
            // honest ceiling beats an optimistic guess here, the same principle this estimator's
            // own "no historical data = no guess" rule already follows.
            long queueDrainSeconds = Math.round((systemWideRemaining * avg) / cap);
            maxRemaining = (maxRemaining == null) ? queueDrainSeconds : Math.max(maxRemaining, queueDrainSeconds);
        }

        return new Estimate(completed, jobs.size(), maxRemaining);
    }

    private static double remainingSecondsFor(JobProgress job, double avg, Instant now) {
        if (job.claimedAt() == null) {
            // Still PENDING (not yet claimed by a worker) - no start time to subtract from, so
            // the full historical average is the best available estimate of its eventual duration.
            return avg;
        }
        double elapsed = Duration.between(job.claimedAt(), now).toSeconds();
        return Math.max(0, avg - elapsed);
    }
}
