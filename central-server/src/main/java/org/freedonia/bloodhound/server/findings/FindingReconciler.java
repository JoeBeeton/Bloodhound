package org.freedonia.bloodhound.server.findings;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Pure dedup/resolution logic for one module's reported findings against a
 * target's currently-OPEN findings for that same module. Deliberately a pure
 * function of its inputs (no repository/DB access) so it's unit-testable
 * without a Spring context - see FindingReconcilerTest.
 *
 * <p>Design decision: a finding that was previously RESOLVED and then
 * reappears is treated as brand new (fresh id, fresh first_detected_scan_run_id)
 * rather than being "reopened" - this falls out naturally from only comparing
 * against {@code currentlyOpen}, which by construction excludes resolved rows.
 */
public final class FindingReconciler {

    private FindingReconciler() {}

    public static ReconciliationPlan reconcile(List<OpenFindingKey> currentlyOpen, List<FindingPayload> reported) {
        Map<String, OpenFindingKey> openByKey =
                currentlyOpen.stream().collect(Collectors.toMap(OpenFindingKey::dedupKey, Function.identity()));

        List<FindingPayload> toInsert = new ArrayList<>();
        List<java.util.UUID> toTouch = new ArrayList<>();
        Set<String> reproducedKeys = new HashSet<>();

        for (FindingPayload finding : reported) {
            String key = finding.ruleId() + " " + finding.affectedAsset();
            reproducedKeys.add(key);
            OpenFindingKey existing = openByKey.get(key);
            if (existing != null) {
                toTouch.add(existing.id());
            } else {
                toInsert.add(finding);
            }
        }

        List<java.util.UUID> toResolve = currentlyOpen.stream()
                .filter(k -> !reproducedKeys.contains(k.dedupKey()))
                .map(OpenFindingKey::id)
                .toList();

        return new ReconciliationPlan(toInsert, toTouch, toResolve);
    }
}
