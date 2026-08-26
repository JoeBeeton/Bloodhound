package org.freedonia.bloodhound.server.findings.dto;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingDetail;
import org.freedonia.bloodhound.server.scoring.ScoreImpact;

public record FindingSummary(
        UUID id,
        UUID targetId,
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

    /**
     * scoreImpact is null when the caller isn't viewing this target's current OPEN
     * findings (e.g. a status=RESOLVED filter) - "what would remediating this improve"
     * only means something for a finding that's still actually open right now.
     */
    public static FindingSummary from(FindingDetail detail, Map<String, Object> evidence, ScoreImpact scoreImpact) {
        Finding finding = detail.finding();
        return new FindingSummary(
                finding.id(),
                finding.targetId(),
                finding.moduleType(),
                finding.ruleId(),
                finding.severity(),
                finding.category(),
                finding.title(),
                finding.description(),
                evidence,
                finding.affectedAsset(),
                finding.firstDetectedScanRunId(),
                finding.status(),
                finding.resolvedAt(),
                finding.createdAt(),
                finding.updatedAt(),
                detail.firstSeenAt(),
                finding.updatedAt(),
                remediationAdviceOrFallback(detail.remediationAdvice(), evidence),
                scoreImpact);
    }

    /**
     * The run-diff view reconstructs historical Finding rows directly (see FindingDiffResponse),
     * without the scan_runs/rules_catalog joins findByTargetDetailed uses - "what would remediating
     * this improve" and a resolved rules_catalog lookup aren't meaningful for a point-in-time
     * historical reconstruction anyway (per the diff feature's original design), so this overload
     * leaves firstSeenAt null and only falls back to evidence.solution for remediation text.
     */
    public static FindingSummary from(Finding finding, Map<String, Object> evidence, ScoreImpact scoreImpact) {
        return new FindingSummary(
                finding.id(),
                finding.targetId(),
                finding.moduleType(),
                finding.ruleId(),
                finding.severity(),
                finding.category(),
                finding.title(),
                finding.description(),
                evidence,
                finding.affectedAsset(),
                finding.firstDetectedScanRunId(),
                finding.status(),
                finding.resolvedAt(),
                finding.createdAt(),
                finding.updatedAt(),
                null,
                finding.updatedAt(),
                remediationAdviceOrFallback(null, evidence),
                scoreImpact);
    }

    /** rules_catalog has no row for ZAP_ALERT_* rule_ids - ZAP supplies its own remediation text into evidence.solution instead. */
    static String remediationAdviceOrFallback(String remediationAdvice, Map<String, Object> evidence) {
        if (remediationAdvice != null && !remediationAdvice.isBlank()) {
            return remediationAdvice;
        }
        Object solution = evidence.get("solution");
        return solution instanceof String s && !s.isBlank() ? s : null;
    }
}
