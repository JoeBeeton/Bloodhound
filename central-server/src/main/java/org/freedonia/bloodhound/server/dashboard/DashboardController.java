package org.freedonia.bloodhound.server.dashboard;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.OrgFinding;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.scoring.ScoreImpact;
import org.freedonia.bloodhound.server.scoring.ScoreImpactCalculator;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Org-overview aggregate for the dashboard - deliberately fanning out to the same repositories
 * the per-target/per-org endpoints already use, rather than a new query language. The one part of
 * this that was a real per-target N+1 (the OWN targets' latest score) is now a single batched
 * query - see ScoreSnapshotRepository#findLatestForTargets - fine at Phase 1 scale (a handful of
 * findings per org) for everything else here.
 */
@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {

    private static final List<String> TOP_FINDING_SEVERITIES = List.of("CRITICAL", "HIGH");
    private static final int TOP_FINDINGS_LIMIT = 10;
    private static final int RECENT_FINDINGS_LIMIT = 10;
    private static final int RECENT_ACTIVITY_LIMIT = 8;

    private final TargetRepository targetRepository;
    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final FindingRepository findingRepository;
    private final ScanRunRepository scanRunRepository;
    private final RuleWeightRepository ruleWeightRepository;
    private final ObjectMapper objectMapper;

    public DashboardController(
            TargetRepository targetRepository,
            ScoreSnapshotRepository scoreSnapshotRepository,
            FindingRepository findingRepository,
            ScanRunRepository scanRunRepository,
            RuleWeightRepository ruleWeightRepository,
            ObjectMapper objectMapper) {
        this.targetRepository = targetRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.findingRepository = findingRepository;
        this.scanRunRepository = scanRunRepository;
        this.ruleWeightRepository = ruleWeightRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping
    public DashboardSummary get(@AuthenticationPrincipal JwtPrincipal principal) {
        UUID orgId = principal.organizationId();
        List<Target> allTargets = targetRepository.findByOrganization(orgId, null, false);

        // Batched into one query rather than one findLatest() call per OWN target - see
        // ScoreSnapshotRepository#findLatestForTargets for the N+1 this replaces.
        List<Target> ownTargetsRaw = allTargets.stream().filter(t -> "OWN".equals(t.targetType())).toList();
        Map<UUID, ScoreSnapshot> latestScoreByTarget =
                scoreSnapshotRepository.findLatestForTargets(ownTargetsRaw.stream().map(Target::id).toList());
        List<TargetSummary> ownTargets = ownTargetsRaw.stream()
                .map(t -> TargetSummary.from(t, latestScoreByTarget.get(t.id())))
                .toList();

        // Score impact needs each target's FULL open set as context (a category's "before"
        // score depends on every open finding in it, not just this severity-filtered
        // top-10 display list) - but only the handful of findings actually being displayed
        // from that target need the expensive per-finding "what if this were resolved"
        // recomputation, not its entire open set. See ScoreImpactCalculator#computeFor -
        // computeAll here was a real, measured problem: a target with ~880 open findings
        // (of which at most a few ever land in the top 10) took the dashboard from ~250ms
        // to 15+ seconds on its own.
        var ruleWeights = ruleWeightRepository.findAllWeights();
        List<OrgFinding> rawTopFindings =
                findingRepository.findOpenByOrganization(orgId, TOP_FINDING_SEVERITIES, TOP_FINDINGS_LIMIT);
        // Purely chronological (all severities), a different ordering from topFindings above -
        // see FindingRepository#findRecentByOrganization's javadoc for why both exist.
        List<OrgFinding> rawRecentFindings = findingRepository.findRecentByOrganization(orgId, RECENT_FINDINGS_LIMIT);

        // Unioned across BOTH lists before any impacts are computed, not built separately per
        // list: impactsByTarget below caches one impacts map per target, computed once on that
        // target's first touch - if topFindings and recentFindings share a target (plausible: a
        // brand-new Critical finding could land in both), building the cache from only one
        // list's displayed-ids would silently miss impacts for whichever finding ids only the
        // other list needed, since the cache is never recomputed after that first touch.
        Map<UUID, Set<UUID>> displayedIdsByTarget = java.util.stream.Stream.concat(
                        rawTopFindings.stream(), rawRecentFindings.stream())
                .collect(Collectors.groupingBy(
                        of -> of.finding().targetId(),
                        Collectors.mapping(of -> of.finding().id(), Collectors.toSet())));
        Map<UUID, Map<UUID, ScoreImpact>> impactsByTarget = new HashMap<>();
        List<OrgFindingSummary> topFindings = rawTopFindings.stream()
                .map(orgFinding -> toSummary(orgFinding, displayedIdsByTarget, impactsByTarget, ruleWeights))
                .toList();
        List<OrgFindingSummary> recentFindings = rawRecentFindings.stream()
                .map(orgFinding -> toSummary(orgFinding, displayedIdsByTarget, impactsByTarget, ruleWeights))
                .toList();

        List<DashboardSummary.RecentActivity> recentActivity = scanRunRepository
                .findRecentByOrganization(orgId, RECENT_ACTIVITY_LIMIT)
                .stream()
                .map(r -> new DashboardSummary.RecentActivity(
                        r.run().id(),
                        r.run().targetId(),
                        r.targetHostname(),
                        r.run().status(),
                        r.run().startedAt(),
                        r.run().completedAt()))
                .toList();

        long ownCount = allTargets.stream().filter(t -> "OWN".equals(t.targetType())).count();
        long competitorCount = allTargets.stream().filter(t -> "COMPETITOR".equals(t.targetType())).count();
        long watchlistCount = allTargets.stream().filter(t -> "WATCHLIST".equals(t.targetType())).count();
        int openCritical = findingRepository.countOpenByOrganization(orgId, List.of("CRITICAL"));
        int openHigh = findingRepository.countOpenByOrganization(orgId, List.of("HIGH"));

        var stats = new DashboardSummary.Stats(
                allTargets.size(), (int) ownCount, (int) competitorCount, (int) watchlistCount, openCritical, openHigh);

        return new DashboardSummary(ownTargets, topFindings, recentFindings, recentActivity, stats);
    }

    private OrgFindingSummary toSummary(
            OrgFinding orgFinding,
            Map<UUID, Set<UUID>> displayedIdsByTarget,
            Map<UUID, Map<UUID, ScoreImpact>> impactsByTarget,
            Map<String, java.math.BigDecimal> ruleWeights) {
        UUID targetId = orgFinding.finding().targetId();
        Map<UUID, ScoreImpact> impacts = impactsByTarget.computeIfAbsent(targetId, id -> {
            var allOpen = findingRepository.findOpenForScoring(id);
            return ScoreImpactCalculator.computeFor(allOpen, displayedIdsByTarget.get(id), ruleWeights);
        });
        ScoreImpact impact = impacts.get(orgFinding.finding().id());
        return OrgFindingSummary.from(orgFinding, parseEvidence(orgFinding.finding().evidenceJson()), impact);
    }

    private Map<String, Object> parseEvidence(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            return Map.of();
        }
    }
}
