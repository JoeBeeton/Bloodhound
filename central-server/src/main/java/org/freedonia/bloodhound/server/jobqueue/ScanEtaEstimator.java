package org.freedonia.bloodhound.server.jobqueue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Estimates how much longer a scan_run has left, from real historical per-module-type
 * average durations (see {@link ScanJobAttemptRepository#averageSecondsByModuleType}).
 * This is a heuristic, not a guarantee: jobs within one scan_run run concurrently across
 * however many workers happen to be free, not strictly sequentially, and worker
 * availability/contention isn't modeled here at all - the ETA is "how long the slowest
 * still-incomplete module has historically taken," not an accounting of actual queueing
 * delay. A module with no historical data yet (e.g. brand new to this deployment)
 * contributes no estimate rather than a fabricated guess.
 */
public final class ScanEtaEstimator {

    private ScanEtaEstimator() {}

    public record JobProgress(String moduleType, String status, Instant claimedAt) {}

    public record Estimate(int completedJobs, int totalJobs, Long etaSeconds) {}

    private static final java.util.Set<String> TERMINAL =
            java.util.Set.of("COMPLETE", "FAILED", "CANCELLED", "UNREACHABLE");

    public static Estimate estimate(List<JobProgress> jobs, Map<String, Double> avgSecondsByModuleType, Instant now) {
        int completed = (int) jobs.stream().filter(j -> TERMINAL.contains(j.status())).count();
        Long maxRemaining = null;
        for (JobProgress job : jobs) {
            if (TERMINAL.contains(job.status())) {
                continue;
            }
            Double avg = avgSecondsByModuleType.get(job.moduleType());
            if (avg == null) {
                continue; // no historical basis for this module type - contributes nothing, not a guess
            }
            double remainingSeconds;
            if (job.claimedAt() != null) {
                double elapsed = Duration.between(job.claimedAt(), now).toSeconds();
                remainingSeconds = Math.max(0, avg - elapsed);
            } else {
                // Still PENDING (not yet claimed by a worker) - no start time to subtract from,
                // so the full historical average is the best available estimate of its eventual duration.
                remainingSeconds = avg;
            }
            long rounded = Math.round(remainingSeconds);
            if (maxRemaining == null || rounded > maxRemaining) {
                maxRemaining = rounded;
            }
        }
        return new Estimate(completed, jobs.size(), maxRemaining);
    }
}
