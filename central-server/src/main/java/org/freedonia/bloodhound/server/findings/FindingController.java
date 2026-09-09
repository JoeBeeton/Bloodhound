package org.freedonia.bloodhound.server.findings;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
    private final AuditLogRepository auditLogRepository;

    public FindingController(
            FindingRepository findingRepository,
            TargetRepository targetRepository,
            ScanRunRepository scanRunRepository,
            RuleWeightRepository ruleWeightRepository,
            ObjectMapper objectMapper,
            AuditLogRepository auditLogRepository) {
        this.findingRepository = findingRepository;
        this.targetRepository = targetRepository;
        this.scanRunRepository = scanRunRepository;
        this.ruleWeightRepository = ruleWeightRepository;
        this.objectMapper = objectMapper;
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Org-wide, cross-target findings - documented as backing the dashboard's "top open
     * findings" widget, but DashboardController actually calls FindingRepository directly for
     * that (its own score-impact-caching needs span two differently-sorted lists at once, see
     * its own javadoc) - this endpoint is the org-wide Findings page (every open finding across
     * every target, filterable and paginated - previously the only ways to see findings were one
     * target at a time, or the dashboard's un-paginated top 10) plus the documented read-only
     * external API. category/offset and the X-Total-Count header are new; severity/limit and the
     * bare-array response body are unchanged so existing API-key integrations keep working.
     *
     * <p>Score impact must be computed from each target's FULL open-findings set (not this
     * filtered, limit-capped display list), since a category's "before" score depends on every
     * open finding in it - so per distinct target_id among the results, fetch that target's
     * complete open set once and reuse it for every displayed finding from that target. The
     * expensive per-finding recomputation itself, though, only runs for the findings actually
     * being displayed (see ScoreImpactCalculator#computeFor) - computeAll here was a real,
     * measured problem against a target with a large open-finding count.
     */
    @GetMapping("/api/v1/findings")
    public ResponseEntity<List<OrgFindingSummary>> forOrganization(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) UUID targetId,
            @RequestParam(defaultValue = "20") int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<String> severities = severity == null || severity.isBlank() ? List.of() : List.of(severity.split(","));
        List<String> categories = category == null || category.isBlank() ? List.of() : List.of(category.split(","));
        int boundedLimit = Math.clamp(limit, 1, MAX_FINDINGS_LIMIT);
        int boundedOffset = Math.max(offset, 0);
        List<OrgFinding> orgFindings = findingRepository.findOpenByOrganization(
                principal.organizationId(), severities, categories, status, search, targetId, boundedLimit, boundedOffset);

        var ruleWeights = ruleWeightRepository.findAllWeights();
        Map<UUID, Set<UUID>> displayedIdsByTarget = orgFindings.stream()
                .collect(Collectors.groupingBy(
                        of -> of.finding().targetId(),
                        Collectors.mapping(of -> of.finding().id(), Collectors.toSet())));
        Map<UUID, Map<UUID, ScoreImpact>> impactsByTarget = new HashMap<>();

        List<OrgFindingSummary> page = orgFindings.stream()
                .map(orgFinding -> {
                    UUID findingTargetId = orgFinding.finding().targetId();
                    Map<UUID, ScoreImpact> impacts = impactsByTarget.computeIfAbsent(findingTargetId, id -> {
                        var allOpen = findingRepository.findOpenForScoring(id);
                        return ScoreImpactCalculator.computeFor(allOpen, displayedIdsByTarget.get(id), ruleWeights);
                    });
                    ScoreImpact impact = impacts.get(orgFinding.finding().id());
                    return OrgFindingSummary.from(orgFinding, parseEvidence(orgFinding.finding().evidenceJson()), impact);
                })
                .toList();
        int totalCount = findingRepository.countOpenByOrganizationFiltered(
                principal.organizationId(), severities, categories, status, search, targetId);
        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
    }

    /**
     * Backs the dedicated Findings Feed page - a product/UX review found the dashboard's fixed
     * top-10 "recent findings" widget was the only chronological (as opposed to severity-ranked)
     * view anywhere in the app, with no way to page further back or narrow by severity/category/
     * target the way the org-wide /findings page already could. Deliberately skips score-impact
     * computation (unlike {@link #forOrganization}): the feed is meant to be lightweight and
     * frequently repolled for a "live" feel, and "what would fixing this improve" is a triage
     * affordance that belongs on the deliberate severity-ranked page, not an ambient activity feed.
     */
    @GetMapping("/api/v1/findings/feed")
    public ResponseEntity<List<OrgFindingSummary>> feed(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) UUID targetId,
            @RequestParam(required = false) LocalDate day,
            @RequestParam(defaultValue = "20") int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<String> severities = severity == null || severity.isBlank() ? List.of() : List.of(severity.split(","));
        List<String> categories = category == null || category.isBlank() ? List.of() : List.of(category.split(","));
        int boundedLimit = Math.clamp(limit, 1, MAX_FINDINGS_LIMIT);
        int boundedOffset = Math.max(offset, 0);
        List<OrgFinding> recent = findingRepository.findRecentByOrganization(
                principal.organizationId(), severities, categories, status, search, targetId, day, boundedLimit, boundedOffset);
        List<OrgFindingSummary> page = recent.stream()
                .map(of -> OrgFindingSummary.from(of, parseEvidence(of.finding().evidenceJson()), null))
                .toList();
        int totalCount = findingRepository.countRecentByOrganization(
                principal.organizationId(), severities, categories, status, search, targetId, day);
        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
    }

    /** The activity histogram at the top of the Findings Feed page - "when did things spike", see {@link FindingRepository#findDailyActivity}. */
    @GetMapping("/api/v1/findings/feed/activity")
    public ResponseEntity<List<FindingRepository.FindingActivityBucket>> feedActivity(
            @RequestParam(defaultValue = "14") int days, @AuthenticationPrincipal JwtPrincipal principal) {
        int boundedDays = Math.clamp(days, 1, 90);
        return ResponseEntity.ok(findingRepository.findDailyActivity(principal.organizationId(), boundedDays));
    }

    /**
     * A product review found no way to export findings across more than one target at a time -
     * even after the org-wide Findings page (GET /api/v1/findings, same filters) shipped, only
     * the single-target export below did. Same MAX_EXPORT_LIMIT/no-score-impact reasoning as
     * that endpoint's own javadoc, just against findOpenByOrganization instead of one target's
     * rows.
     */
    @GetMapping(value = "/api/v1/findings/export", produces = "text/csv")
    public ResponseEntity<byte[]> exportForOrganization(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) UUID targetId,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<String> severities = severity == null || severity.isBlank() ? List.of() : List.of(severity.split(","));
        List<String> categories = category == null || category.isBlank() ? List.of() : List.of(category.split(","));
        List<OrgFinding> orgFindings = findingRepository.findOpenByOrganization(
                principal.organizationId(), severities, categories, status, search, targetId, MAX_EXPORT_LIMIT, 0);
        List<OrgFindingSummary> summaries = orgFindings.stream()
                .map(of -> OrgFindingSummary.from(of, parseEvidence(of.finding().evidenceJson()), null))
                .toList();
        byte[] csv = FindingCsvWriter.writeOrgWide(summaries).getBytes(StandardCharsets.UTF_8);
        String filename = "bloodhound-findings-" + LocalDate.now() + ".csv";
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(csv);
    }

    /** Generous enough that the overwhelming majority of targets see everything in one request, without risking the multi-minute/multi-MB response an unbounded query against a large target produces - confirmed live, 36,466 open findings for one target in this deployment. */
    private static final int DEFAULT_FINDINGS_LIMIT = 200;

    private static final int MAX_FINDINGS_LIMIT = 500;

    @GetMapping("/api/v1/targets/{id}/findings")
    public ResponseEntity<List<FindingSummary>> forTarget(
            @PathVariable UUID id,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String affectedAsset,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "" + DEFAULT_FINDINGS_LIMIT) int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(FindingController::notFound);
        return list(target.id(), severity, category, status, affectedAsset, search, limit, offset);
    }

    /**
     * Deliberately bounded, not truly unbounded - the exact "SELECT f.* with no cap" shape
     * that {@link FindingRepository#findByTargetDetailed}'s own javadoc documents as a real
     * production incident (a 36,466-open-finding target, 16MB response, over two minutes with
     * no result). 50,000 is comfortably above that observed real-world maximum while still
     * protecting the server from an unbounded response if a target's finding count grows far
     * past anything seen so far - score-impact computation is skipped entirely here (unlike the
     * paginated list endpoint), since "what would remediating this improve" is an interactive
     * prioritization aid, not something a static report row needs.
     */
    private static final int MAX_EXPORT_LIMIT = 50_000;

    @GetMapping(value = "/api/v1/targets/{id}/findings/export", produces = "text/csv")
    public ResponseEntity<byte[]> exportForTarget(
            @PathVariable UUID id,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String affectedAsset,
            @RequestParam(required = false) String search,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(FindingController::notFound);
        var rows = findingRepository.findByTargetDetailed(
                target.id(), severity, category, status, affectedAsset, search, MAX_EXPORT_LIMIT, 0);
        List<FindingSummary> summaries = rows.stream()
                .map(d -> FindingSummary.from(d, parseEvidence(d.finding().evidenceJson()), null))
                .toList();
        byte[] csv = FindingCsvWriter.write(summaries).getBytes(StandardCharsets.UTF_8);
        String filename = sanitizeFilename(target.hostname()) + "-findings-" + LocalDate.now() + ".csv";
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(csv);
    }

    /** hostname is user-supplied at target creation - strip anything that could break a quoted Content-Disposition filename. */
    private static String sanitizeFilename(String hostname) {
        return hostname.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    @GetMapping("/api/v1/runs/{runId}/findings")
    public ResponseEntity<List<FindingSummary>> forRun(
            @PathVariable UUID runId,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String affectedAsset,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "" + DEFAULT_FINDINGS_LIMIT) int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        ScanRun run = scanRunRepository.findById(runId).orElseThrow(FindingController::notFound);
        Target target = targetRepository
                .findByIdAndOrganization(run.targetId(), principal.organizationId())
                .orElseThrow(FindingController::notFound);
        return list(target.id(), severity, category, status, affectedAsset, search, limit, offset);
    }

    /**
     * scoreImpact is always computed from the target's full OPEN set (ignoring whatever
     * severity/category/status filter the caller passed for display), so a category's
     * "before" score is never wrong due to a filtered/partial view - a displayed finding
     * that isn't actually OPEN (e.g. a status=RESOLVED query) simply won't be in that
     * map and gets scoreImpact=null, since "what would remediating this improve" only
     * means something for a finding that's still open right now.
     *
     * <p>Response body shape is unchanged (a bare JSON array) to keep every existing
     * frontend caller working - the total count of matching findings (which can be far
     * larger than what's actually returned) is carried in the X-Total-Count header
     * instead, same convention as SubdomainController#list. Only the rows actually
     * shipped are limited; the score-impact computation above still sees every open
     * finding for correctness (see ScoreImpactCalculator's own javadoc for why this
     * being O(n log n) now, not O(n²), makes that affordable even for a large target).
     */
    private ResponseEntity<List<FindingSummary>> list(
            UUID targetId,
            String severity,
            String category,
            String status,
            String affectedAsset,
            String search,
            int limit,
            int offset) {
        int boundedLimit = Math.clamp(limit, 1, MAX_FINDINGS_LIMIT);
        int boundedOffset = Math.max(offset, 0);

        var displayed = findingRepository.findByTargetDetailed(
                targetId, severity, category, status, affectedAsset, search, boundedLimit, boundedOffset);
        var allOpen = findingRepository.findOpenForScoring(targetId);
        var ruleWeights = ruleWeightRepository.findAllWeights();
        Set<UUID> displayedIds = displayed.stream().map(d -> d.finding().id()).collect(Collectors.toSet());
        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeFor(allOpen, displayedIds, ruleWeights);

        List<FindingSummary> page = displayed.stream()
                .map(d -> FindingSummary.from(d, parseEvidence(d.finding().evidenceJson()), impacts.get(d.finding().id())))
                .toList();
        int totalCount =
                findingRepository.countByTargetFiltered(targetId, severity, category, status, affectedAsset, search);

        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
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

    /** See UserSelfController's own WeakPasswordResponse / SlackIntegrationController's own ErrorMessageResponse for why a real body, not a thrown ResponseStatusException, is needed for a message the caller is actually meant to see - this app's default error handler never exposes a ResponseStatusException's reason text. */
    public record ErrorMessageResponse(String message) {}

    /**
     * A product review found FindingReconciler's automatic OPEN-&gt;RESOLVED transition (fires
     * only once a scan no longer detects an issue - see its own javadoc) was the ONLY way a
     * finding's status ever changed: a false positive or an accepted-risk finding just sat as
     * OPEN indefinitely, with no way for an analyst to say "reviewed, doesn't need action" short
     * of waiting for the underlying condition to change. DISMISSED is a sticky human override -
     * see V48__findings_dismissed_status.sql's own comment for why FindingReconciler never
     * touches one either direction once set.
     */
    @PostMapping("/api/v1/findings/{id}/dismiss")
    public ResponseEntity<?> dismissFinding(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Finding finding = requireOwnedFinding(id, principal);
        if (findingRepository.dismiss(id) == 0) {
            // Only reachable via a race (another request changed the status between the lookup
            // above and this UPDATE) or a direct API call against an already-non-OPEN finding -
            // reported distinctly from NOT_FOUND so a caller can tell "exists but isn't open"
            // apart from "doesn't exist/isn't yours".
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorMessageResponse("only an open finding can be dismissed"));
        }
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "FINDING_DISMISSED",
                "FINDING",
                id.toString(),
                "ruleId=" + finding.ruleId() + " affectedAsset=" + finding.affectedAsset());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/findings/{id}/reopen")
    public ResponseEntity<?> reopenFinding(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Finding finding = requireOwnedFinding(id, principal);
        if (findingRepository.reopen(id) == 0) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorMessageResponse("only a dismissed finding can be reopened"));
        }
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "FINDING_REOPENED",
                "FINDING",
                id.toString(),
                "ruleId=" + finding.ruleId() + " affectedAsset=" + finding.affectedAsset());
        return ResponseEntity.noContent().build();
    }

    /** Same "mismatch reads as not found, not forbidden" reasoning as TargetController#requireOwnedTarget. */
    private Finding requireOwnedFinding(UUID id, JwtPrincipal principal) {
        Finding finding = findingRepository.findById(id).orElseThrow(FindingController::notFound);
        targetRepository.findByIdAndOrganization(finding.targetId(), principal.organizationId()).orElseThrow(FindingController::notFound);
        return finding;
    }

    private static void requireWriteAccess(JwtPrincipal principal) {
        if (!"ADMIN".equals(principal.role()) && !"ANALYST".equals(principal.role())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ADMIN or ANALYST role required");
        }
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
