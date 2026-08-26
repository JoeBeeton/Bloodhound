package org.freedonia.bloodhound.server.findings;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.scoring.ScoreImpact;
import org.freedonia.bloodhound.server.scoring.ScoreImpactCalculator;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Findings are a target-level rolling set (see FindingReconciler), not
 * literally scoped to one run except via first_detected_scan_run_id. So
 * GET /runs/{runId}/findings resolves the run's target and returns that
 * target's current findings (same query as the target endpoint) rather than
 * "only findings inserted by this exact run" - the more useful and less
 * surprising interpretation for a UI showing "what does this run's target
 * look like right now".
 */
@RestController
public class FindingController {

    private final FindingRepository findingRepository;
    private final TargetRepository targetRepository;
    private final ScanRunRepository scanRunRepository;
    private final RuleWeightRepository ruleWeightRepository;
    private final ObjectMapper objectMapper;

    public FindingController(
            FindingRepository findingRepository,
            TargetRepository targetRepository,
            ScanRunRepository scanRunRepository,
            RuleWeightRepository ruleWeightRepository,
            ObjectMapper objectMapper) {
        this.findingRepository = findingRepository;
        this.targetRepository = targetRepository;
        this.scanRunRepository = scanRunRepository;
        this.ruleWeightRepository = ruleWeightRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Org-wide, cross-target findings - backs the dashboard's "top open findings" widget.
     * Score impact must be computed from each target's FULL open-findings set (not this
     * severity-filtered, limit-capped display list), since a category's "before" score
     * depends on every open finding in it - so per distinct target_id among the results,
     * fetch that target's complete open set once and reuse it for every displayed finding
     * from that target.
     */
    @GetMapping("/api/v1/findings")
    public List<OrgFindingSummary> forOrganization(
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "20") int limit,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<String> severities = severity == null || severity.isBlank()
                ? List.of()
                : List.of(severity.split(","));
        List<OrgFinding> orgFindings =
                findingRepository.findOpenByOrganization(principal.organizationId(), severities, limit);

        var ruleWeights = ruleWeightRepository.findAllWeights();
        Map<UUID, Map<UUID, ScoreImpact>> impactsByTarget = new HashMap<>();

        return orgFindings.stream()
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
    }

    @GetMapping("/api/v1/targets/{id}/findings")
    public List<FindingSummary> forTarget(
            @PathVariable UUID id,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String affectedAsset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(FindingController::notFound);
        return list(target.id(), severity, category, status, affectedAsset);
    }

    @GetMapping("/api/v1/runs/{runId}/findings")
    public List<FindingSummary> forRun(
            @PathVariable UUID runId,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String affectedAsset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        ScanRun run = scanRunRepository.findById(runId).orElseThrow(FindingController::notFound);
        Target target = targetRepository
                .findByIdAndOrganization(run.targetId(), principal.organizationId())
                .orElseThrow(FindingController::notFound);
        return list(target.id(), severity, category, status, affectedAsset);
    }

    /**
     * scoreImpact is always computed from the target's full OPEN set (ignoring whatever
     * severity/category/status filter the caller passed for display), so a category's
     * "before" score is never wrong due to a filtered/partial view - a displayed finding
     * that isn't actually OPEN (e.g. a status=RESOLVED query) simply won't be in that
     * map and gets scoreImpact=null, since "what would remediating this improve" only
     * means something for a finding that's still open right now.
     */
    private List<FindingSummary> list(UUID targetId, String severity, String category, String status, String affectedAsset) {
        var displayed = findingRepository.findByTargetDetailed(targetId, severity, category, status, affectedAsset);
        var allOpen = findingRepository.findByTarget(targetId, null, null, null);
        var ruleWeights = ruleWeightRepository.findAllWeights();
        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(allOpen, ruleWeights);

        return displayed.stream()
                .map(d -> FindingSummary.from(d, parseEvidence(d.finding().evidenceJson()), impacts.get(d.finding().id())))
                .toList();
    }

    private Map<String, Object> parseEvidence(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return Map.of();
        }
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
