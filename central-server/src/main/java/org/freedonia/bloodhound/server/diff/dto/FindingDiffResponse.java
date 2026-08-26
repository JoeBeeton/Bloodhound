package org.freedonia.bloodhound.server.diff.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.diff.FindingDiffResult;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;

public record FindingDiffResponse(
        UUID targetId,
        UUID baselineRunId,
        Instant baselineComputedAt,
        UUID compareRunId,
        Instant compareComputedAt,
        List<FindingSummary> newFindings,
        List<FindingSummary> resolvedFindings,
        List<FindingSummary> unchangedFindings,
        List<SeverityChangeSummary> changedSeverity) {

    /** baselineRun is null when the compared run is a target's first scan - see DiffController. */
    public static FindingDiffResponse from(
            UUID targetId, ScanRun baselineRun, ScanRun compareRun, FindingDiffResult result, ObjectMapper objectMapper) {
        return new FindingDiffResponse(
                targetId,
                baselineRun != null ? baselineRun.id() : null,
                baselineRun != null ? baselineRun.completedAt() : null,
                compareRun.id(),
                compareRun.completedAt(),
                result.newFindings().stream().map(f -> summarize(f, objectMapper)).toList(),
                result.resolvedFindings().stream().map(f -> summarize(f, objectMapper)).toList(),
                result.unchangedFindings().stream().map(f -> summarize(f, objectMapper)).toList(),
                result.changedSeverity().stream()
                        .map(c -> new SeverityChangeSummary(summarize(c.before(), objectMapper), summarize(c.after(), objectMapper)))
                        .toList());
    }

    /**
     * scoreImpact is deliberately omitted (null) here: these findings are a point-in-time
     * reconstruction of what was open as of a *historical* scan run (see FindingRepository
     * #findOpenAsOf), not the target's current open set - "what would remediating this
     * improve" isn't a meaningful question against a historical snapshot, and correctly
     * computing it against the *current* set for a possibly-already-resolved finding would
     * need real additional plumbing (a target-id + current-open-findings lookup threaded
     * through DiffController) that isn't justified for this view. The main findings list
     * and dashboard top-findings widget - the two places this was actually requested for -
     * both carry it correctly.
     */
    private static FindingSummary summarize(Finding finding, ObjectMapper objectMapper) {
        return FindingSummary.from(finding, parseEvidence(finding.evidenceJson(), objectMapper), null);
    }

    private static Map<String, Object> parseEvidence(String json, ObjectMapper objectMapper) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new com.fasterxml.jackson.core.type.TypeReference<>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return Map.of();
        }
    }

    public record SeverityChangeSummary(FindingSummary before, FindingSummary after) {}
}
