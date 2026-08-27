package org.freedonia.bloodhound.server.scoring;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.springframework.stereotype.Service;

/** Thin transactional shell around the pure {@link ScoringEngine}: fetch open findings + rule weights, compute, persist. */
@Service
public class ScoreSnapshotService {

    private final FindingRepository findingRepository;
    private final RuleWeightRepository ruleWeightRepository;
    private final ScoreSnapshotRepository scoreSnapshotRepository;

    public ScoreSnapshotService(
            FindingRepository findingRepository,
            RuleWeightRepository ruleWeightRepository,
            ScoreSnapshotRepository scoreSnapshotRepository) {
        this.findingRepository = findingRepository;
        this.ruleWeightRepository = ruleWeightRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
    }

    /**
     * WEB_APP (ZAP/Nuclei active-scan findings) is exclusively produced by Tier 2 modules -
     * there is no Tier 1 equivalent - but unlike NETWORK_ANONYMOUS_FTP/NETWORK_FULL_PORT_SURFACE
     * it can't be excluded via {@link RuleWeightRepository#findTier2ExclusiveRuleIds()}: ZAP's
     * and Nuclei's rule_ids are dynamically generated per plugin/template ("ZAP_ALERT_10202",
     * "NUCLEI_cve-2023-1234"), so there are no rules_catalog rows for them to flag in the first
     * place (see ZapAlertMapper/NucleiFindingMapper's own javadoc). Excluded by category instead.
     */
    private static final String TIER2_ONLY_CATEGORY = "WEB_APP";

    /**
     * Computes and persists a score_snapshots row from the target's currently-OPEN findings -
     * both the full score (all open findings) and a Tier-1-only "fair comparison" score
     * (excluding findings only a Tier 2 deep scan could have produced), using the identical
     * {@link ScoringEngine} algorithm for both. Tier 2 only ever runs against explicitly
     * authorized targets - in practice, your own domains - so without this split, an owned
     * target that's been deep-scanned looks artificially worse than a competitor that never
     * had the chance to accumulate those findings.
     */
    public ScoreSnapshot computeAndPersist(UUID targetId, UUID scanRunId) {
        List<Finding> openFindings = findingRepository.findOpenForScoring(targetId);
        var ruleWeights = ruleWeightRepository.findAllWeights();

        ScoreResult full = ScoringEngine.compute(openFindings, ruleWeights);

        Set<String> tier2ExclusiveRuleIds = ruleWeightRepository.findTier2ExclusiveRuleIds();
        List<Finding> tier1Findings = openFindings.stream()
                .filter(f -> !tier2ExclusiveRuleIds.contains(f.ruleId()))
                .filter(f -> !TIER2_ONLY_CATEGORY.equals(f.category()))
                .toList();
        ScoreResult tier1Only = ScoringEngine.compute(tier1Findings, ruleWeights);

        return scoreSnapshotRepository.insert(targetId, scanRunId, full, tier1Only);
    }
}
