package org.freedonia.bloodhound.server.findings;

import java.time.Instant;
import java.util.UUID;

public record Finding(
        UUID id,
        /** "bh-&lt;target-hostname&gt;-&lt;n&gt;", a stable per-target sequential label - see V33__finding_display_id.sql. Null on rows from FindingRepository's lean scoring projection, which never needs it. */
        String displayId,
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
