package org.freedonia.bloodhound.server.findings.dto;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.OrgFinding;
import org.freedonia.bloodhound.server.scoring.ScoreImpact;

/** FindingSummary plus the owning target's hostname - what the dashboard's cross-target "top findings" widget needs. */
public record OrgFindingSummary(
        UUID id,
        String displayId,
        UUID targetId,
        String targetHostname,
        String moduleType,
        String ruleId,
        String severity,
        String category,
        String title,
        String description,
        Map<String, Object> evidence,
        String affectedAsset,
        UUID firstDetectedScanRunId,
        String status,
        Instant resolvedAt,
        Instant createdAt,
        Instant updatedAt,
        Instant firstSeenAt,
        Instant lastSeenAt,
        String remediationAdvice,
        ScoreImpact scoreImpact) {

    public static OrgFindingSummary from(OrgFinding orgFinding, Map<String, Object> evidence, ScoreImpact scoreImpact) {
        var f = orgFinding.finding();
        return new OrgFindingSummary(
                f.id(),
                f.displayId(),
                f.targetId(),
                orgFinding.targetHostname(),
                f.moduleType(),
                f.ruleId(),
                f.severity(),
                f.category(),
                f.title(),
                f.description(),
                evidence,
                f.affectedAsset(),
                f.firstDetectedScanRunId(),
                f.status(),
                f.resolvedAt(),
                f.createdAt(),
                f.updatedAt(),
                orgFinding.firstSeenAt(),
                f.updatedAt(),
                FindingSummary.remediationAdviceOrFallback(orgFinding.remediationAdvice(), evidence),
                scoreImpact);
    }
}
