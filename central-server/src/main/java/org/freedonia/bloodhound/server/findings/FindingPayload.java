package org.freedonia.bloodhound.server.findings;

import java.util.Map;

/**
 * Wire shape of a single finding reported by a worker in a job result.
 * Independently mirrors worker's own FindingPayload - the two are two copies
 * of one contract, not a shared type, matching how ClaimedJob/ClaimedJobDto
 * already do this across the module boundary.
 */
public record FindingPayload(
        String ruleId,
        String severity,
        String category,
        String title,
        String description,
        String affectedAsset,
        Map<String, Object> evidence) {}
