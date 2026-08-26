package org.freedonia.bloodhound.server.jobqueue.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** One row of the /api/v1/scans/active list - a currently-RUNNING scan_run with live progress/ETA. */
public record ActiveScan(
        UUID id,
        UUID targetId,
        String targetHostname,
        String triggeredBy,
        Instant startedAt,
        int completedJobs,
        int totalJobs,
        Long etaSeconds,
        List<ModuleProgress> modules) {
    /** {@code host} is only present for Tier 2 (one-job-per-host) jobs - see JobPayloadHost. */
    public record ModuleProgress(String moduleType, String status, String host) {}
}
