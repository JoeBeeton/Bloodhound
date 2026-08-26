package org.freedonia.bloodhound.server.diff;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * Pure set-difference between two point-in-time snapshots of a target's open
 * findings (see {@link org.freedonia.bloodhound.server.findings.FindingRepository#findOpenAsOf}),
 * keyed by (ruleId, affectedAsset) - the same dedup key the reconciliation
 * pipeline uses elsewhere. No DB access here, so this is unit-testable
 * without a Spring context; {@link DiffController} does the run-lookup and
 * point-in-time-reconstruction plumbing around it.
 *
 * <p>A finding resolved and then reappearing (fresh id, fresh
 * first_detected_scan_run_id per {@link org.freedonia.bloodhound.server.findings.FindingReconciler}'s
 * design) entirely between the two compared points in time falls out
 * correctly without any special-casing: both the "before" instance and the
 * "after" instance share the same (ruleId, affectedAsset) key even though
 * they're different rows, so they land in {@code unchangedFindings} (or
 * {@code changedSeverity} if the severity differs) rather than being seen as
 * both resolved and new.
 */
public final class FindingDiffEngine {

    private FindingDiffEngine() {}

    public static FindingDiffResult diff(List<Finding> before, List<Finding> after) {
        Map<String, Finding> beforeByKey = byKey(before);
        Map<String, Finding> afterByKey = byKey(after);

        List<Finding> newFindings = new ArrayList<>();
        List<Finding> unchanged = new ArrayList<>();
        List<FindingDiffResult.SeverityChange> changedSeverity = new ArrayList<>();

        for (Map.Entry<String, Finding> entry : afterByKey.entrySet()) {
            Finding beforeFinding = beforeByKey.get(entry.getKey());
            Finding afterFinding = entry.getValue();
            if (beforeFinding == null) {
                newFindings.add(afterFinding);
            } else if (beforeFinding.severity().equals(afterFinding.severity())) {
                unchanged.add(afterFinding);
            } else {
                changedSeverity.add(new FindingDiffResult.SeverityChange(beforeFinding, afterFinding));
            }
        }

        List<Finding> resolvedFindings = new ArrayList<>();
        for (Map.Entry<String, Finding> entry : beforeByKey.entrySet()) {
            if (!afterByKey.containsKey(entry.getKey())) {
                resolvedFindings.add(entry.getValue());
            }
        }

        return new FindingDiffResult(newFindings, resolvedFindings, unchanged, changedSeverity);
    }

    private static Map<String, Finding> byKey(List<Finding> findings) {
        // LinkedHashMap: stable, input-order iteration for deterministic test assertions.
        Map<String, Finding> byKey = new LinkedHashMap<>();
        for (Finding finding : findings) {
            byKey.put(key(finding), finding);
        }
        return byKey;
    }

    private static String key(Finding finding) {
        return finding.ruleId() + " " + finding.affectedAsset();
    }
}
