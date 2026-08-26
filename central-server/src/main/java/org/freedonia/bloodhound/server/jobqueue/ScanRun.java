package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.UUID;

public record ScanRun(
        UUID id,
        UUID targetId,
        String triggeredBy,
        UUID triggeredByUserId,
        Instant startedAt,
        Instant completedAt,
        String status) {}
