package org.freedonia.bloodhound.server.findings;

import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

/** Thin transactional shell around the pure {@link FindingReconciler}: fetch open findings, plan, then write the plan. */
@Service
public class ResultIngestionService {

    private static final Logger log = LoggerFactory.getLogger(ResultIngestionService.class);

    private final FindingRepository findingRepository;

    public ResultIngestionService(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    public void ingest(UUID scanRunId, UUID targetId, String moduleType, List<FindingPayload> reported) {
        List<OpenFindingKey> currentlyOpen = findingRepository.findOpenKeys(targetId, moduleType);
        ReconciliationPlan plan = FindingReconciler.reconcile(currentlyOpen, reported);

        plan.toInsert().forEach(payload -> insertTolerant(scanRunId, targetId, moduleType, payload));
        if (!plan.toTouch().isEmpty()) {
            findingRepository.touch(plan.toTouch(), scanRunId);
        }
        if (!plan.toResolve().isEmpty()) {
            findingRepository.resolve(plan.toResolve());
        }
    }

    /**
     * FindingReconciler dedupes within one module's own reported batch (the bug actually seen
     * live - see its own javadoc), but this plan was computed from a findOpenKeys() snapshot
     * that a second, truly concurrent ingest() call for the same target/module (e.g. two
     * overlapping scan runs) could invalidate between that read and this write - the same race
     * shape, just across two separate calls instead of within one. idx_findings_target_rule_asset_open
     * (see its migration) is the DB-level backstop: a conflict here means the other call's insert
     * already landed the exact row this one was trying to create, which is exactly the outcome
     * this insert wanted, so it's swallowed rather than failing the whole ingest.
     */
    private void insertTolerant(UUID scanRunId, UUID targetId, String moduleType, FindingPayload payload) {
        try {
            findingRepository.insert(scanRunId, targetId, moduleType, payload);
        } catch (DuplicateKeyException e) {
            log.debug(
                    "duplicate OPEN finding for target={} rule={} asset={} - already inserted by a concurrent ingest",
                    targetId,
                    payload.ruleId(),
                    payload.affectedAsset());
        }
    }
}
