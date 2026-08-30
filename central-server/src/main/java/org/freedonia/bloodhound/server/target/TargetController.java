package org.freedonia.bloodhound.server.target;

import jakarta.validation.Valid;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.dto.CreateTargetRequest;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.freedonia.bloodhound.server.target.dto.UpdateTargetRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/targets")
public class TargetController {

    private final TargetRepository targetRepository;
    private final ScanRunService scanRunService;
    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final AuditLogRepository auditLogRepository;

    public TargetController(
            TargetRepository targetRepository,
            ScanRunService scanRunService,
            ScoreSnapshotRepository scoreSnapshotRepository,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            AuditLogRepository auditLogRepository) {
        this.targetRepository = targetRepository;
        this.scanRunService = scanRunService;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    public List<TargetSummary> list(
            @RequestParam(required = false) String type,
            @RequestParam(required = false, defaultValue = "false") boolean includeInactive,
            @AuthenticationPrincipal JwtPrincipal principal) {
        // One latest-score (+ now last-scan) lookup per target - fine at Phase 1 scale (a handful
        // of targets per org); a batched query is a candidate optimization if
        // that stops being true.
        return targetRepository.findByOrganization(principal.organizationId(), type, includeInactive).stream()
                .map(this::composeSummary)
                .toList();
    }

    /**
     * Composes the score + last-scan-time/tier fields every TargetSummary needs - lastScanAt
     * prefers completedAt, falling back to startedAt for a run still in progress (or one that
     * never completed cleanly), so "last scan" always reflects the most recent real activity
     * rather than going blank while a scan is running. lastScanWasDeep asks ScanJobRepository
     * whether that run queued any Tier 2 module type (see ScanRunService#allTier2ModuleTypes,
     * the single source of truth for tier classification - a scan run has no tier column of its
     * own, tier is purely a property of which modules got queued under it).
     */
    private TargetSummary composeSummary(Target target) {
        var latestScore = scoreSnapshotRepository.findLatest(target.id()).orElse(null);
        var lastScan = scanRunRepository.findMostRecentByTarget(target.id()).orElse(null);
        Instant lastScanAt = null;
        Boolean lastScanWasDeep = null;
        if (lastScan != null) {
            lastScanAt = lastScan.completedAt() != null ? lastScan.completedAt() : lastScan.startedAt();
            lastScanWasDeep =
                    scanJobRepository.existsForRunWithModuleTypeIn(lastScan.id(), ScanRunService.allTier2ModuleTypes());
        }
        return TargetSummary.from(target, latestScore, lastScanAt, lastScanWasDeep);
    }

    @PostMapping
    public ResponseEntity<TargetSummary> create(
            @Valid @RequestBody CreateTargetRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        rejectUnsafeHostname(request.hostname());
        try {
            Target target = targetRepository.insert(principal.organizationId(), request.hostname(), request.targetType());
            return ResponseEntity.status(HttpStatus.CREATED).body(TargetSummary.from(target));
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "target already tracked for this organization");
        }
    }

    /**
     * SSRF guard: this hostname is about to be handed to workers that will
     * make real outbound HTTP/DNS/scan requests to it. Reject anything
     * that's an IP literal (or, right now, resolves) into a private/loopback/
     * link-local/reserved range - most importantly 169.254.169.254, the cloud
     * metadata address on AWS/GCP/Azure, which the hostname regex alone
     * doesn't catch since it's syntactically a valid "domain name" to that
     * pattern. Deliberately does NOT reject an unresolvable hostname (a
     * target's apex commonly has no A/AAAA record of its own - this is a
     * real pattern already seen in this system - while its
     * subdomains, discovered later by SUBDOMAIN_ENUM, do resolve and get
     * scanned); this check only blocks hostnames that resolve to somewhere
     * unsafe *right now*, not ones that don't resolve at all. This is a
     * point-in-time check, not a substitute for validating the resolved
     * address again immediately before each outbound connection (DNS is
     * attacker-controlled and can change between now and scan time) - see
     * SafeAddressValidator's javadoc.
     */
    private static void rejectUnsafeHostname(String hostname) {
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
        } catch (IOException e) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "hostname resolves to a private, loopback, or reserved address and cannot be tracked as a target");
        }
    }

    @GetMapping("/{id}")
    public TargetSummary get(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = requireOwnedTarget(id, principal);
        return composeSummary(target);
    }

    @PatchMapping("/{id}")
    public TargetSummary update(
            @PathVariable UUID id,
            @RequestBody UpdateTargetRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        requireOwnedTarget(id, principal);
        targetRepository.updateCadenceAndActive(id, request.scanCadenceSeconds(), request.isActive());
        // Omitted (null) means "this request isn't touching notes" (e.g. the Remove/Restore
        // toggle only ever sends isActive) - a caller that does mean to update notes always sends
        // the field, blank string included, since that's how a save from an emptied textarea
        // looks. See UpdateTargetRequest's own javadoc for why this field alone doesn't follow
        // the plain "null = unchanged" convention scanCadenceSeconds/isActive use.
        if (request.notes() != null) {
            targetRepository.updateNotes(id, request.notes());
        }
        return TargetSummary.from(targetRepository.findById(id).orElseThrow());
    }

    /**
     * Hard, cascading delete (findings/subdomains/scan_runs/score_snapshots/
     * whois_records/target_authorizations all carry ON DELETE CASCADE FKs to
     * targets - see V3__targets_and_jobs.sql) - irreversible, wipes the
     * target's entire audit history. Distinct from PATCH .../{id} with
     * isActive=false ("Remove" in the UI), which only pauses scanning and
     * keeps everything - that's what most "delete" clicks actually mean and
     * stays fully reversible.
     *
     * <p>Two deliberate guard rails beyond the normal write-access check,
     * given a single click here is unrecoverable: (1) restricted to ADMIN
     * only, not ANALYST - see {@link #requireAdmin} - and (2) only reachable
     * once a target has already been soft-removed (isActive=false), so
     * permanently destroying a target's history is always a second,
     * separate action taken after already deciding to stop monitoring it,
     * never a single click away from an actively-monitored target.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireAdmin(principal);
        Target target = requireOwnedTarget(id, principal);
        if (target.isActive()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "target must be removed (isActive=false) before it can be permanently deleted");
        }
        targetRepository.delete(id);
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "TARGET_DELETED",
                "TARGET",
                id.toString(),
                "hostname=" + target.hostname());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<ScanRunSummary> scanNow(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        requireOwnedTarget(id, principal);
        requireNoRunInFlight(id);
        ScanRun run = scanRunService.createManualScan(id, principal.userId());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ScanRunSummary(run.id(), run.targetId(), run.status(), run.startedAt()));
    }

    @PostMapping("/{id}/scan/deep")
    public ResponseEntity<ScanRunSummary> deepScanNow(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Target target = requireOwnedTarget(id, principal);
        // The one place this gets checked - see ScanRunService#createDeepScan's
        // javadoc. Server-side, not just a disabled button in the UI: a direct
        // API call against an unauthorized target must fail the same way.
        if (!"AUTHORIZED".equals(target.authorizationStatus())) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "target is not authorized for Tier 2 active scanning");
        }
        requireNoRunInFlight(id);
        ScanRun run = scanRunService.createDeepScan(id, principal.userId());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ScanRunSummary(run.id(), run.targetId(), run.status(), run.startedAt()));
    }

    /**
     * A security/reliability review found neither manual trigger had ever checked this -
     * {@link org.freedonia.bloodhound.server.jobqueue.ScanAutoScheduler} already guards its own
     * cadence-driven scans against exactly this race (see its own use of the same repository
     * method), but a human clicking "Scan now" twice quickly, or the new bulk "Scan N selected"
     * action on the Targets page firing many requests in parallel against targets that may
     * already have a cadence-scheduled scan mid-flight, could previously enqueue a second full
     * set of Tier 1/2 jobs for the same target concurrently - double the real outbound traffic
     * against the actual scanned domain, and two ScanRuns racing to reconcile the same findings
     * set against each other's still-in-progress results. Reported as 409, not silently ignored,
     * so a caller (the UI, an API-key integration) can tell "didn't start because one's already
     * running" apart from a real failure.
     */
    private void requireNoRunInFlight(UUID targetId) {
        if (scanRunRepository.existsRunningForTarget(targetId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "a scan is already running for this target");
        }
    }

    private Target requireOwnedTarget(UUID id, JwtPrincipal principal) {
        return targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private static void requireWriteAccess(JwtPrincipal principal) {
        if (!"ADMIN".equals(principal.role()) && !"ANALYST".equals(principal.role())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ADMIN or ANALYST role required");
        }
    }

    private static void requireAdmin(JwtPrincipal principal) {
        if (!"ADMIN".equals(principal.role())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ADMIN role required");
        }
    }

    public record ScanRunSummary(UUID id, UUID targetId, String status, java.time.Instant startedAt) {}
}
