package org.freedonia.bloodhound.server.mcp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.jobqueue.OrgScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanJobAttemptRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunDetailComposer;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScansController;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Read-only MCP tools exposing the same data surface as the existing read-only external API (see
 * apikey.ApiKeyController) - no write tools in this first version (no resolve-finding, no
 * trigger-scan), matching the deliberate read-only scope decision. Every method composes its
 * response directly from the same repositories the equivalent REST controller already uses
 * (TargetController, FindingController, SubdomainController, RunController, ScansController) -
 * following this codebase's existing convention that read-path composition lives at the call
 * site, not behind a separate service layer (see ScanRunDetailComposer's javadoc for the one
 * exception, extracted because RunController and this class both needed it verbatim).
 *
 * <p>Org-scoping is read from the current request's validated MCP access token (see
 * McpTokenCustomizer for where org_id/user_id are added at issuance), not from any tool
 * parameter - a client can never ask to see another organization's data by simply passing a
 * different id, the same guarantee JwtPrincipal gives every ordinary controller.
 *
 * <p>scoreImpact is always passed as null when reusing FindingSummary/OrgFindingSummary's
 * from(...) factories - it's an expensive, UI-only "what would fixing this improve" computation
 * (see ScoreImpactCalculator), not something a tool-calling agent asking "what's open" needs.
 */
@Component
public class McpReadTools {

    private final TargetRepository targetRepository;
    private final FindingRepository findingRepository;
    private final SubdomainRepository subdomainRepository;
    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;
    private final ObjectMapper objectMapper;

    public McpReadTools(
            TargetRepository targetRepository,
            FindingRepository findingRepository,
            SubdomainRepository subdomainRepository,
            ScoreSnapshotRepository scoreSnapshotRepository,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            ObjectMapper objectMapper) {
        this.targetRepository = targetRepository;
        this.findingRepository = findingRepository;
        this.subdomainRepository = subdomainRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.objectMapper = objectMapper;
    }

    @McpTool(
            name = "list_targets",
            description = "List every attack-surface target being monitored for the caller's organization, with its latest score/grade.",
            annotations = @McpTool.McpAnnotations(title = "List targets", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public List<TargetSummary> listTargets(
            @McpToolParam(description = "Optional target type filter (e.g. DOMAIN)", required = false) String targetType,
            @McpToolParam(description = "Include soft-removed/inactive targets", required = false) Boolean includeInactive) {
        return targetRepository.findByOrganization(currentOrganizationId(), targetType, Boolean.TRUE.equals(includeInactive))
                .stream()
                .map(t -> TargetSummary.from(t, scoreSnapshotRepository.findLatest(t.id()).orElse(null)))
                .toList();
    }

    @McpTool(
            name = "get_target",
            description = "Get a single target's detail, including its latest score/grade.",
            annotations = @McpTool.McpAnnotations(title = "Get target", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public TargetSummary getTarget(@McpToolParam(description = "Target id", required = true) UUID targetId) {
        Target target = requireOwnedTarget(targetId);
        return TargetSummary.from(target, scoreSnapshotRepository.findLatest(target.id()).orElse(null));
    }

    @McpTool(
            name = "list_findings_for_target",
            description = "List findings for a single target, optionally filtered by severity/category/status/affected asset.",
            annotations = @McpTool.McpAnnotations(title = "List findings for target", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public List<FindingSummary> listFindingsForTarget(
            @McpToolParam(description = "Target id", required = true) UUID targetId,
            @McpToolParam(description = "Comma-separated severities (CRITICAL,HIGH,MEDIUM,LOW,INFO)", required = false)
                    String severity,
            @McpToolParam(description = "Comma-separated categories", required = false) String category,
            @McpToolParam(description = "Finding status - defaults to OPEN", required = false) String status,
            @McpToolParam(description = "Exact affected-asset filter", required = false) String affectedAsset,
            @McpToolParam(description = "Max rows to return (default 200, capped at 500)", required = false) Integer limit,
            @McpToolParam(description = "Offset for pagination", required = false) Integer offset) {
        requireOwnedTarget(targetId);
        int boundedLimit = Math.clamp(limit != null ? limit : 200, 1, 500);
        int boundedOffset = offset != null ? Math.max(offset, 0) : 0;
        return findingRepository
                .findByTargetDetailed(targetId, severity, category, status, affectedAsset, null, boundedLimit, boundedOffset)
                .stream()
                .map(d -> FindingSummary.from(d, parseEvidence(d.finding().evidenceJson()), null))
                .toList();
    }

    @McpTool(
            name = "list_open_findings_for_organization",
            description = "List open findings across every target in the caller's organization, most severe first.",
            annotations = @McpTool.McpAnnotations(title = "List open findings for organization", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public List<OrgFindingSummary> listOpenFindingsForOrganization(
            @McpToolParam(description = "Comma-separated severities (CRITICAL,HIGH,MEDIUM,LOW,INFO)", required = false)
                    String severity,
            @McpToolParam(description = "Max rows to return (default 50, capped at 500)", required = false) Integer limit) {
        List<String> severities =
                severity == null || severity.isBlank() ? List.of() : List.of(severity.split(","));
        int boundedLimit = Math.clamp(limit != null ? limit : 50, 1, 500);
        return findingRepository
                .findOpenByOrganization(currentOrganizationId(), severities, boundedLimit)
                .stream()
                .map(f -> OrgFindingSummary.from(f, parseEvidence(f.finding().evidenceJson()), null))
                .toList();
    }

    @McpTool(
            name = "list_subdomains",
            description = "List discovered subdomains for a target, optionally filtered by a hostname substring.",
            annotations = @McpTool.McpAnnotations(title = "List subdomains", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public List<SubdomainSummary> listSubdomains(
            @McpToolParam(description = "Target id", required = true) UUID targetId,
            @McpToolParam(description = "Case-insensitive hostname substring filter", required = false) String hostnameContains,
            @McpToolParam(description = "Max rows to return (default 200, capped at 500)", required = false) Integer limit,
            @McpToolParam(description = "Offset for pagination", required = false) Integer offset) {
        requireOwnedTarget(targetId);
        int boundedLimit = Math.clamp(limit != null ? limit : 200, 1, 500);
        int boundedOffset = offset != null ? Math.max(offset, 0) : 0;
        return subdomainRepository.findByTarget(targetId, hostnameContains, boundedLimit, boundedOffset).stream()
                .map(SubdomainSummary::from)
                .toList();
    }

    @McpTool(
            name = "get_scan_run",
            description = "Get a scan run's full detail, including every job's per-attempt history and captured worker log output.",
            annotations = @McpTool.McpAnnotations(title = "Get scan run", readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    public ScanRunDetail getScanRun(@McpToolParam(description = "Scan run id", required = true) UUID runId) {
        return ScanRunDetailComposer.compose(
                        runId,
                        currentOrganizationId(),
                        scanRunRepository,
                        scanJobRepository,
                        scanJobAttemptRepository,
                        targetRepository)
                .orElseThrow(() -> new IllegalArgumentException("no scan run with that id in your organization"));
    }

    @McpTool(
            name = "list_active_scans",
            description = "List every scan run currently in progress for the caller's organization.",
            annotations = @McpTool.McpAnnotations(title = "List active scans", readOnlyHint = true, destructiveHint = false, idempotentHint = false, openWorldHint = false))
    public List<ScansController.RecentScan> listActiveScans() {
        return scanRunRepository.findRunningByOrganization(currentOrganizationId()).stream()
                .map(McpReadTools::toRecentScan)
                .toList();
    }

    @McpTool(
            name = "list_recent_scans",
            description = "List recent scan runs (any status) for the caller's organization, most recent first.",
            annotations = @McpTool.McpAnnotations(title = "List recent scans", readOnlyHint = true, destructiveHint = false, idempotentHint = false, openWorldHint = false))
    public List<ScansController.RecentScan> listRecentScans(
            @McpToolParam(description = "Max rows to return (default 30, capped at 500)", required = false) Integer limit) {
        int boundedLimit = Math.clamp(limit != null ? limit : 30, 1, 500);
        return scanRunRepository.findRecentByOrganization(currentOrganizationId(), boundedLimit).stream()
                .map(McpReadTools::toRecentScan)
                .toList();
    }

    private static ScansController.RecentScan toRecentScan(OrgScanRun r) {
        return new ScansController.RecentScan(
                r.run().id(),
                r.run().targetId(),
                r.targetHostname(),
                r.run().triggeredBy(),
                r.run().status(),
                r.run().startedAt(),
                r.run().completedAt());
    }

    private Target requireOwnedTarget(UUID targetId) {
        return targetRepository
                .findByIdAndOrganization(targetId, currentOrganizationId())
                .orElseThrow(() -> new IllegalArgumentException("no target with that id in your organization"));
    }

    /**
     * The resource-server chain (see McpSecurityConfig) leaves the validated Jwt as the
     * SecurityContext's Authentication principal - org_id is one of the custom claims
     * McpTokenCustomizer adds to every access token at issuance, mirroring what JwtPrincipal
     * carries for the ordinary session-JWT auth path every controller uses.
     *
     * <p>McpEnabledGuardFilter already rejects a token with no org_id claim before any tool method
     * runs, so in practice this can't be reached without one - but a security review flagged the
     * original UUID.fromString(null) here as an unhandled-NPE-on-500 trap rather than a clean
     * 401, so this doesn't rely purely on filter-ordering to stay safe.
     */
    private UUID currentOrganizationId() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!(principal instanceof Jwt jwt)) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED);
        }
        String orgId = jwt.getClaimAsString("org_id");
        if (orgId == null) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN);
        }
        return UUID.fromString(orgId);
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
