package org.freedonia.bloodhound.server.findings;

import java.util.List;
import java.util.UUID;

/**
 * Output of {@link FindingReconciler#reconcile}: what to do with one module's
 * reported findings for one target, against its currently-OPEN findings.
 *
 * @param toInsert new findings not currently open for their (ruleId, affectedAsset)
 * @param toTouch  ids of currently-open findings reproduced again this run (bump updated_at/scan_run_id, no duplicate row)
 * @param toResolve ids of currently-open findings NOT reproduced this run (mark RESOLVED)
 */
public record ReconciliationPlan(List<FindingPayload> toInsert, List<UUID> toTouch, List<UUID> toResolve) {}
