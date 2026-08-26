package org.freedonia.bloodhound.server.dashboard;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.OrgFinding;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.scoring.ScoreImpact;
import org.freedonia.bloodhound.server.scoring.ScoreImpactCalculator;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Org-overview aggregate for the dashboard - deliberately one round trip
 * fanning out to the same repositories the per-target/per-org endpoints
 * already use, rather than a new query language. Fine at Phase 1 scale (a
 * handful of targets/findings per org), same judgment call TargetController
 * already made for its per-target score lookups.
 */
@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {

    private static final List<String> TOP_FINDING_SEVERITIES = List.of("CRITICAL", "HIGH");
    private static final int TOP_FINDINGS_LIMIT = 10;
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

        List<TargetSummary> ownTargets = allTargets.stream()
                .filter(t -> "OWN".equals(t.targetType()))
                .map(t -> TargetSummary.from(t, scoreSnapshotRepository.findLatest(t.id()).orElse(null)))
                .toList();

        // Same per-target caching as FindingController#forOrganization: score impact needs
        // each target's FULL open set, not this severity-filtered top-10 display list.
        var ruleWeights = ruleWeightRepository.findAllWeights();
        Map<UUID, Map<UUID, ScoreImpact>> impactsByTarget = new HashMap<>();
        List<OrgFinding> rawTopFindings =
                findingRepository.findOpenByOrganization(orgId, TOP_FINDING_SEVERITIES, TOP_FINDINGS_LIMIT);
        List<OrgFindingSummary> topFindings = rawTopFindings.stream()
                .map(orgFinding -> {
                    UUID targetId = orgFinding.finding().targetId();
                    Map<UUID, ScoreImpact> impacts = impactsByTarget.computeIfAbsent(targetId, id -> {
                        var allOpen = findingRepository.findByTarget(id, null, null, null);
                        return ScoreImpactCalculator.computeAll(allOpen, ruleWeights);
                    });
                    ScoreImpact impact = impacts.get(orgFinding.finding().id());
                    return OrgFindingSummary.from(orgFinding, parseEvidence(orgFinding.finding().evidenceJson()), impact);
                })
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

        return new DashboardSummary(ownTargets, topFindings, recentActivity, stats);
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
