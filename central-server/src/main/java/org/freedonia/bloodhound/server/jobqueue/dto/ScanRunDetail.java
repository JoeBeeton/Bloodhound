package org.freedonia.bloodhound.server.jobqueue.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ScanRunDetail(
        UUID id,
        UUID targetId,
        String targetHostname,
        String triggeredBy,
        Instant startedAt,
        Instant completedAt,
        String status,
        List<ScanJobStatus> jobs) {
    public record ScanJobStatus(
            UUID id,
            String moduleType,
            String status,
            int attemptCount,
            int maxAttempts,
            String errorDetail,
            List<Attempt> attempts,
            /** The specific host this job scans - only present for Tier 2 (one-job-per-host) jobs, see JobPayloadHost. */
            String host) {}

    /** One row of a job's full retry history - see ScanJobAttemptRepository. */
    public record Attempt(
            int attemptNumber,
            String claimedBy,
            Instant startedAt,
            Instant endedAt,
            String outcome,
            String errorDetail,
            /** Captured worker log output for this attempt - see JobLogCapture (worker). Null, not empty, when nothing was captured. */
            String logOutput) {}
}
