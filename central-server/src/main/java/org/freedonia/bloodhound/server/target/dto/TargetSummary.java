package org.freedonia.bloodhound.server.target.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingRepository.WafStatus;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.target.Target;

public record TargetSummary(
        UUID id,
        String hostname,
        String targetType,
        String authorizationStatus,
        int scanCadenceSeconds,
        Instant nextScanAt,
        boolean isActive,
        Instant createdAt,
        BigDecimal overallScore,
        String grade,
        // "Fair comparison" score excluding Tier 2-exclusive findings - null on targets that
        // haven't been scanned since this was added.
        BigDecimal tier1OverallScore,
        String tier1Grade,
        /** Absent (null) until this target has had its first scan (CT_CHECK/CVE_CORRELATION don't count - see ScanRunRepository#findMostRecentByTarget). */
        Instant lastScanAt,
        /** Null alongside lastScanAt when there's no scan yet; otherwise true for a Tier 2 deep scan, false for a regular Tier 1 scan. */
        Boolean lastScanWasDeep,
        String notes,
        /** Same meaning as SubdomainSummary's own wafVendor - the WAF nuclei identified on this target's own apex hostname, if any. */
        String wafVendor,
        /** Same meaning as SubdomainSummary's own wafScanned. */
        boolean wafScanned) {

    /** No scan has ever completed for this target yet - score/grade are absent, not zero. */
    public static TargetSummary from(Target target) {
        return from(target, null, null, null, null);
    }

    public static TargetSummary from(Target target, ScoreSnapshot latestScore) {
        return from(target, latestScore, null, null, null);
    }

    public static TargetSummary from(
            Target target, ScoreSnapshot latestScore, Instant lastScanAt, Boolean lastScanWasDeep) {
        return from(target, latestScore, lastScanAt, lastScanWasDeep, null);
    }

    public static TargetSummary from(
            Target target, ScoreSnapshot latestScore, Instant lastScanAt, Boolean lastScanWasDeep, WafStatus wafStatus) {
        return new TargetSummary(
                target.id(),
                target.hostname(),
                target.targetType(),
                target.authorizationStatus(),
                target.scanCadenceSeconds(),
                target.nextScanAt(),
                target.isActive(),
                target.createdAt(),
                latestScore != null ? latestScore.overallScore() : null,
                latestScore != null ? latestScore.grade() : null,
                latestScore != null ? latestScore.tier1OverallScore() : null,
                latestScore != null ? latestScore.tier1Grade() : null,
                lastScanAt,
                lastScanWasDeep,
                target.notes(),
                wafStatus != null ? wafStatus.vendor() : null,
                wafStatus != null && wafStatus.scanned());
    }
}
