package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.UUID;

public record ScanJob(
        UUID id,
        UUID scanRunId,
        UUID targetId,
        String moduleType,
        String status,
        short priority,
        Instant runAfter,
        String claimedBy,
        Instant claimedAt,
        Instant leaseExpiresAt,
        int attemptCount,
        int maxAttempts,
        String payloadJson,
        String resultMetadataJson,
        String errorDetail,
        Instant createdAt) {}
