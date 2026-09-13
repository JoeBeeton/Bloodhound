package org.freedonia.bloodhound.server.findings;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

/** Thin transactional shell around the pure {@link FindingReconciler}: fetch open findings, plan, then write the plan. */
@Service
public class ResultIngestionService {

    private static final Logger log = LoggerFactory.getLogger(ResultIngestionService.class);

    private final FindingRepository findingRepository;
    private final RuleWeightRepository ruleWeightRepository;
    private final TargetRepository targetRepository;

    public ResultIngestionService(
            FindingRepository findingRepository,
            RuleWeightRepository ruleWeightRepository,
            TargetRepository targetRepository) {
        this.findingRepository = findingRepository;
        this.ruleWeightRepository = ruleWeightRepository;
        this.targetRepository = targetRepository;
    }

    /**
     * @param scanScope the single host this batch of results covers, when the job was one of the
     *     per-host Tier 2 jobs ScanRunService#createDeepScan fans out - or null when the results
     *     speak for the whole target. Findings outside the scope are neither touched nor resolved:
     *     a per-host job reporting nothing about host B says nothing about host B. Before this
     *     existed, every Tier 2 finding flapped RESOLVED/re-OPEN on every deep scan as sibling
     *     host jobs completed - see V53__findings_scan_scope.sql.
     */
    public void ingest(
            UUID scanRunId, UUID targetId, String moduleType, String scanScope, List<FindingPayload> reported) {
        // A product/AppSec review found rules_catalog.enabled was completely inert - not
        // checked anywhere. Filtering here (before reconciliation, not after) means a disabled
        // rule's findings are never persisted at all, AND any of its findings already open from
        // before it was disabled get resolved on this target's next scan - FindingReconciler
        // treats "not in this run's reported batch" as "no longer present" regardless of why,
        // so this needs no separate cleanup logic of its own.
        //
        // Resolved here (not threaded through every one of this method's own callers -
        // JobLifecycleService, VulnerabilityCorrelationScheduler, CompoundRiskAnalysisService) so
        // there's exactly one place that maps "which org's disabled-rules apply" from a targetId -
        // a security review found the org-scoping fix for this (see RuleWeightRepository's own
        // javadoc) landing everywhere at once was less error-prone than updating each call site to
        // separately look up and pass an organizationId through.
        UUID organizationId = targetRepository
                .findById(targetId)
                .map(org.freedonia.bloodhound.server.target.Target::organizationId)
                .orElse(null);
        Set<String> disabledRuleIds =
                organizationId != null ? ruleWeightRepository.findDisabledRuleIds(organizationId) : Set.of();
        List<FindingPayload> allowed =
                disabledRuleIds.isEmpty() ? reported : reported.stream().filter(f -> !disabledRuleIds.contains(f.ruleId())).toList();

        List<OpenFindingKey> currentlyOpen = findingRepository.findOpenKeys(targetId, moduleType, scanScope);
        ReconciliationPlan plan = FindingReconciler.reconcile(currentlyOpen, allowed);

        plan.toInsert().forEach(payload -> insertTolerant(scanRunId, targetId, moduleType, scanScope, payload));
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
    private void insertTolerant(
            UUID scanRunId, UUID targetId, String moduleType, String scanScope, FindingPayload payload) {
        try {
            findingRepository.insert(scanRunId, targetId, moduleType, scanScope, payload);
        } catch (DuplicateKeyException e) {
            log.debug(
                    "duplicate OPEN finding for target={} rule={} asset={} - already inserted by a concurrent ingest",
                    targetId,
                    payload.ruleId(),
                    payload.affectedAsset());
        }
    }
}
