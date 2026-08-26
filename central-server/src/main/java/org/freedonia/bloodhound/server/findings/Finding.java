package org.freedonia.bloodhound.server.findings;

import java.time.Instant;
import java.util.UUID;

public record Finding(
        UUID id,
        UUID scanRunId,
        UUID targetId,
        String moduleType,
        String ruleId,
        String severity,
        String category,
        String title,
        String description,
        String evidenceJson,
        String affectedAsset,
        UUID firstDetectedScanRunId,
        String status,
        Instant resolvedAt,
        Instant createdAt,
        Instant updatedAt) {}
