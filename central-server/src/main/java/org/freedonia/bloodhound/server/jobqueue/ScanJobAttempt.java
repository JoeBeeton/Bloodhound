package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.UUID;

public record ScanJobAttempt(
        UUID id,
        UUID scanJobId,
        int attemptNumber,
        String claimedBy,
        Instant startedAt,
        Instant endedAt,
        String outcome,
        String errorDetail,
        String logOutput) {}
