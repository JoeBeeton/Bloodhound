package org.freedonia.bloodhound.server.findings;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Output of {@link FindingReconciler#reconcile}: what to do with one module's
 * reported findings for one target, against its currently-OPEN findings.
 *
 * @param toInsert new findings not currently open for their (ruleId, affectedAsset)
 * @param toTouch  ids of currently-open findings reproduced again this run (bump updated_at/scan_run_id, no duplicate row)
 * @param toResolve ids of currently-open findings NOT reproduced this run (mark RESOLVED)
 * @param reproducedPayloads for each id in toTouch, the payload that reproduced it - its current
 *     severity/title/description/evidence replace the stored ones, so a re-graded rule (or fresher
 *     evidence) reaches findings that were already open, not just newly inserted ones
 */
public record ReconciliationPlan(
        List<FindingPayload> toInsert,
        List<UUID> toTouch,
        List<UUID> toResolve,
        Map<UUID, FindingPayload> reproducedPayloads) {}
