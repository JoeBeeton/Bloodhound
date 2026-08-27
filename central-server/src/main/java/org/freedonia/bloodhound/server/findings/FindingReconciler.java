package org.freedonia.bloodhound.server.findings;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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

        // Keyed maps/sets, not plain lists: a real duplicate-finding bug was caused by
        // `reported` itself containing more than one payload for the same (ruleId,
        // affectedAsset) - confirmed live, DOCUMENT_METADATA fans out over a target's root
        // plus every known subdomain (see HostFanOut), and when the same document is linked
        // from more than one of those hostnames, each host's scan independently downloads
        // and parses it, producing byte-for-byte duplicate findings that all land in one
        // `reported` list for a single ingest() call. Without this, three duplicates reported
        // meant three rows in toInsert. The first occurrence of a given key wins - arbitrary,
        // but no less arbitrary than which host HostFanOut happened to schedule first.
        Map<String, FindingPayload> toInsertByKey = new LinkedHashMap<>();
        Set<java.util.UUID> toTouch = new LinkedHashSet<>();
        Set<String> reproducedKeys = new HashSet<>();

        for (FindingPayload finding : reported) {
            String key = finding.ruleId() + " " + finding.affectedAsset();
            reproducedKeys.add(key);
            OpenFindingKey existing = openByKey.get(key);
            if (existing != null) {
                toTouch.add(existing.id());
            } else {
                toInsertByKey.putIfAbsent(key, finding);
            }
        }

        List<java.util.UUID> toResolve = currentlyOpen.stream()
                .filter(k -> !reproducedKeys.contains(k.dedupKey()))
                .map(OpenFindingKey::id)
                .toList();

        return new ReconciliationPlan(List.copyOf(toInsertByKey.values()), List.copyOf(toTouch), toResolve);
    }
}
