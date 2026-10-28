package org.freedonia.bloodhound.server.target;

import jakarta.validation.Valid;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.JobProgress;
import org.freedonia.bloodhound.server.jobqueue.ScanJobAttemptRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.freedonia.bloodhound.server.target.TargetBulkCreateRateLimiter.TargetBulkCreateRateLimitedException;
import org.freedonia.bloodhound.server.target.dto.BulkCreateTargetsRequest;
import org.freedonia.bloodhound.server.target.dto.CreateTargetRequest;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.freedonia.bloodhound.server.target.dto.UpdateTargetRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
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

    /** How many recent real completions to average per module_type - see ScanJobAttemptRepository, same sample size ScansController's ETA uses. */
    private static final int ETA_SAMPLE_SIZE = 30;

    private final TargetRepository targetRepository;
    private final ScanRunService scanRunService;
    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;
    private final TargetAuthorizationRepository targetAuthorizationRepository;
    private final AuditLogRepository auditLogRepository;
    private final TargetBulkCreateRateLimiter targetBulkCreateRateLimiter;
    private final FindingRepository findingRepository;
    private final SubdomainRepository subdomainRepository;
    private final int maxTargetsPerOrg;

    public TargetController(
            TargetRepository targetRepository,
            ScanRunService scanRunService,
            ScoreSnapshotRepository scoreSnapshotRepository,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            TargetAuthorizationRepository targetAuthorizationRepository,
            AuditLogRepository auditLogRepository,
            TargetBulkCreateRateLimiter targetBulkCreateRateLimiter,
            FindingRepository findingRepository,
            SubdomainRepository subdomainRepository,
            @Value("${bloodhound.targets.max-per-org:100}") int maxTargetsPerOrg) {
        this.targetRepository = targetRepository;
        this.scanRunService = scanRunService;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.targetAuthorizationRepository = targetAuthorizationRepository;
        this.auditLogRepository = auditLogRepository;
        this.targetBulkCreateRateLimiter = targetBulkCreateRateLimiter;
        this.findingRepository = findingRepository;
        this.subdomainRepository = subdomainRepository;
        this.maxTargetsPerOrg = maxTargetsPerOrg;
    }

    @GetMapping
    public List<TargetSummary> list(
            @RequestParam(required = false) String type,
            @RequestParam(required = false, defaultValue = "false") boolean includeInactive,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<Target> targets = targetRepository.findByOrganization(principal.organizationId(), type, includeInactive);
        // Batched into one query rather than one findLatest() call per target - see
        // ScoreSnapshotRepository#findLatestForTargets for the N+1 this replaces. The
        // last-scan-run and Tier 2 lookups below remain one-per-target - still fine at Phase 1
        // scale (a handful of targets per org); a further batched query is a candidate
        // optimization if that stops being true.
        Map<UUID, ScoreSnapshot> latestScoreByTarget =
                scoreSnapshotRepository.findLatestForTargets(targets.stream().map(Target::id).toList());
        // One shared historical-average lookup for every target in this response, not one per
        // target - same reasoning as ScansController's identical call for its own ETA.
        Map<String, Double> avgSecondsByModuleType = scanJobAttemptRepository.averageSecondsByModuleType(ETA_SAMPLE_SIZE);
        // Same reasoning for the ZAP_ACTIVE_SCAN concurrency-cap queue depth - one global slot
        // shared across every org/target's scan_run, not something to look up per target - see
        // ScansController#active for the identical pattern and ScanEtaEstimator's own javadoc on
        // why the queue-depth model is needed at all for this module type.
        Map<String, Integer> concurrencyCaps = Map.of("ZAP_ACTIVE_SCAN", scanJobRepository.zapMaxConcurrentScans());
        Map<String, Integer> systemWideRemaining = new java.util.HashMap<>();
        concurrencyCaps.keySet().forEach(
                moduleType -> systemWideRemaining.put(moduleType, scanJobRepository.countPendingOrInProgress(moduleType)));
        return targets.stream()
                .map(t -> composeSummary(t, latestScoreByTarget.get(t.id()), avgSecondsByModuleType, concurrencyCaps, systemWideRemaining))
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
        return composeSummary(target, scoreSnapshotRepository.findLatest(target.id()).orElse(null));
    }

    /** Same as {@link #composeSummary(Target)}, but takes an already-fetched score - see {@link #list} for why. */
    private TargetSummary composeSummary(Target target, ScoreSnapshot latestScore) {
        Map<String, Integer> concurrencyCaps = Map.of("ZAP_ACTIVE_SCAN", scanJobRepository.zapMaxConcurrentScans());
        Map<String, Integer> systemWideRemaining = new java.util.HashMap<>();
        concurrencyCaps.keySet().forEach(
                moduleType -> systemWideRemaining.put(moduleType, scanJobRepository.countPendingOrInProgress(moduleType)));
        return composeSummary(
                target,
                latestScore,
                scanJobAttemptRepository.averageSecondsByModuleType(ETA_SAMPLE_SIZE),
                concurrencyCaps,
                systemWideRemaining);
    }

    /** Same as {@link #composeSummary(Target, ScoreSnapshot)}, but takes already-fetched shared lookups - see {@link #list} for why. */
    private TargetSummary composeSummary(
            Target target,
            ScoreSnapshot latestScore,
            Map<String, Double> orgAvgSecondsByModuleType,
            Map<String, Integer> concurrencyCapByModuleType,
            Map<String, Integer> systemWideRemainingByModuleType) {
        var lastScan = scanRunRepository.findMostRecentByTarget(target.id()).orElse(null);
        Instant lastScanAt = null;
        Boolean lastScanWasDeep = null;
        if (lastScan != null) {
            lastScanAt = lastScan.completedAt() != null ? lastScan.completedAt() : lastScan.startedAt();
            lastScanWasDeep =
                    scanJobRepository.existsForRunWithModuleTypeIn(lastScan.id(), ScanRunService.allTier2ModuleTypes());
        }
        // Only the apex hostname's own entry is needed here - see SubdomainController for the
        // identical per-host lookup driving the map's subdomain-level WAF badges.
        var wafStatus = findingRepository.findWafStatusByTarget(target.id()).get(target.hostname());
        // Per-target history first (a module's duration, SUBDOMAIN_ENUM especially, genuinely
        // varies by target - see ScanJobAttemptRepository#averageSecondsByModuleType(UUID, int)),
        // falling back to the org-wide map for any module type this target hasn't got enough of
        // its own completions for yet. Without this fallback every target would show the same
        // number only once it had accrued its own full history, which defeats the point.
        Map<String, Double> targetAvgSecondsByModuleType =
                scanJobAttemptRepository.averageSecondsByModuleType(target.id(), ETA_SAMPLE_SIZE);
        Long estimatedScanDurationSeconds =
                estimateTier1ScanDurationSeconds(targetAvgSecondsByModuleType, orgAvgSecondsByModuleType);
        Long estimatedTier2ScanDurationSeconds = estimateTier2ScanDurationSeconds(
                target,
                targetAvgSecondsByModuleType,
                orgAvgSecondsByModuleType,
                concurrencyCapByModuleType,
                systemWideRemainingByModuleType);
        return TargetSummary.from(
                target,
                latestScore,
                lastScanAt,
                lastScanWasDeep,
                wafStatus,
                estimatedScanDurationSeconds,
                estimatedTier2ScanDurationSeconds);
    }

    /**
     * A not-yet-started Tier 1 scan's modules all run concurrently, not sequentially (same model
     * {@link org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator} already uses for an
     * in-progress run's uncapped module types) - so the whole run's duration is approximated as
     * the slowest individual module type's own historical average, not their sum. Null when none
     * of {@link ScanRunService#allTier1ModuleTypes()} has any historical data yet (in either map),
     * rather than a fabricated guess.
     */
    private static Long estimateTier1ScanDurationSeconds(
            Map<String, Double> targetAvgSecondsByModuleType, Map<String, Double> orgAvgSecondsByModuleType) {
        Long max = null;
        for (String moduleType : ScanRunService.allTier1ModuleTypes()) {
            Double avg = targetAvgSecondsByModuleType.get(moduleType);
            if (avg == null) {
                avg = orgAvgSecondsByModuleType.get(moduleType);
            }
            if (avg == null) {
                continue;
            }
            long rounded = Math.round(avg);
            if (max == null || rounded > max) {
                max = rounded;
            }
        }
        return max;
    }

    /**
     * A not-yet-started Tier 2 (deep) scan's duration, only for a target whose
     * authorization_status is AUTHORIZED - the only state {@link #deepScanNow} will actually run
     * one for; null for every other target, since estimating a scan that can't be launched would
     * be misleading, not helpful. Reuses {@link ScanEtaEstimator} directly rather than the simpler
     * max-of-averages model {@link #estimateTier1ScanDurationSeconds} uses: unlike Tier 1, Tier 2's
     * fan-out module types run once per selected host (see ScanRunService#createDeepScan), and
     * ZAP_ACTIVE_SCAN specifically shares one global concurrency-capped slot across every org's
     * scan runs - ignoring either of those was confirmed (see ScanEtaEstimator's own javadoc) to
     * under-estimate a real deep scan by an order of magnitude. Synthesizes one PENDING,
     * not-yet-claimed job per (fan-out module type, selected host) pair plus one per target-scoped
     * module type, mirroring createDeepScan's own job counts exactly, then asks the same estimator
     * an in-progress run's remaining time uses what a run starting from zero would take.
     */
    private Long estimateTier2ScanDurationSeconds(
            Target target,
            Map<String, Double> targetAvgSecondsByModuleType,
            Map<String, Double> orgAvgSecondsByModuleType,
            Map<String, Integer> concurrencyCapByModuleType,
            Map<String, Integer> systemWideRemainingByModuleType) {
        if (!"AUTHORIZED".equals(target.authorizationStatus())) {
            return null;
        }
        int subdomainCount = subdomainRepository.countByTarget(target.id(), null, null);
        int fanoutHostCount = 1 + Math.min(subdomainCount, ScanRunService.tier2SubdomainCap());

        List<JobProgress> syntheticJobs = new ArrayList<>();
        for (String moduleType : ScanRunService.tier2FanoutModuleTypes()) {
            for (int i = 0; i < fanoutHostCount; i++) {
                syntheticJobs.add(new JobProgress(moduleType, "PENDING", null));
            }
        }
        for (String moduleType : ScanRunService.tier2TargetScopedModuleTypes()) {
            syntheticJobs.add(new JobProgress(moduleType, "PENDING", null));
        }

        // This hypothetical run's own capped-module jobs don't exist in scan_jobs yet, so the real
        // current system-wide queue depth (necessarily counting only already-inserted jobs from
        // OTHER runs) doesn't include them. Add them in explicitly - otherwise a target whose own
        // future deep scan would add, say, 16 ZAP_ACTIVE_SCAN jobs behind the current global queue
        // would be estimated as if it only had to wait for everyone else's jobs, understating its
        // own (often dominant) contribution to the very queue it's about to join.
        Map<String, Integer> adjustedSystemWideRemainingByModuleType =
                new java.util.HashMap<>(systemWideRemainingByModuleType);
        for (String moduleType : concurrencyCapByModuleType.keySet()) {
            long ownJobCount =
                    syntheticJobs.stream().filter(job -> moduleType.equals(job.moduleType())).count();
            adjustedSystemWideRemainingByModuleType.merge(moduleType, (int) ownJobCount, Integer::sum);
        }

        // Target history wins over the org-wide fallback for any module type both maps have an
        // entry for - same preference order as estimateTier1ScanDurationSeconds above.
        Map<String, Double> mergedAvgSecondsByModuleType = new java.util.HashMap<>(orgAvgSecondsByModuleType);
        mergedAvgSecondsByModuleType.putAll(targetAvgSecondsByModuleType);

        return ScanEtaEstimator.estimate(
                        syntheticJobs,
                        mergedAvgSecondsByModuleType,
                        adjustedSystemWideRemainingByModuleType,
                        concurrencyCapByModuleType,
                        Instant.now())
                .etaSeconds();
    }

    @PostMapping
    public ResponseEntity<TargetSummary> create(
            @Valid @RequestBody CreateTargetRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        requireUnderTargetCap(principal.organizationId(), 1);
        rejectUnsafeHostname(request.hostname());
        try {
            Target target = targetRepository.insert(principal.organizationId(), request.hostname(), request.targetType());
            return ResponseEntity.status(HttpStatus.CREATED).body(TargetSummary.from(target));
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "target already tracked for this organization");
        }
    }

    /**
     * A security review found this had no cap at all - every tracked target drives real,
     * periodic outbound scanning against a real external host, so unbounded creation is unbounded
     * scanning traffic, the same abuse category scanCadenceSeconds' own @Min/@Max bounds guard
     * against via a different field. Checked against active targets only - see
     * TargetRepository#countActiveByOrganization's own comment for why a soft-removed one doesn't
     * count. additionalCount lets createBulk below check "would adding N more exceed the cap"
     * without a separate near-identical method.
     */
    private void requireUnderTargetCap(UUID organizationId, int additionalCount) {
        int current = targetRepository.countActiveByOrganization(organizationId);
        if (current + additionalCount > maxTargetsPerOrg) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "organization has reached its limit of " + maxTargetsPerOrg + " active targets");
        }
    }

    public record BulkCreateTargetResult(String hostname, boolean created, String error, TargetSummary target) {
        static BulkCreateTargetResult success(String hostname, TargetSummary target) {
            return new BulkCreateTargetResult(hostname, true, null, target);
        }

        static BulkCreateTargetResult failure(String hostname, String error) {
            return new BulkCreateTargetResult(hostname, false, error, null);
        }
    }

    /**
     * A product review found onboarding a domain portfolio meant submitting each hostname
     * one-by-one through POST .../targets, same one-at-a-time gap the page's own bulk-scan/bulk-
     * remove actions already closed for existing targets. Reuses create()'s own per-hostname
     * validation (format, SSRF, duplicate) and the same org cap, but imperatively rather than via
     * bean validation - see BulkCreateTargetsRequest's own javadoc for why a batch can't just
     * reuse @Valid the way a single create does. One bad or duplicate hostname in an otherwise
     * good batch becomes one failed result alongside the rest of the batch's successes, not a
     * whole-request 400 - the point of a bulk endpoint over N individual POSTs is exactly that
     * partial-success tolerance.
     *
     * <p>Rate-limited (TargetBulkCreateRateLimiter, keyed by user id) on top of the per-hostname
     * validation above - a security review found this had no limit on how often it could be
     * called at all: each call runs a real synchronous DNS lookup per hostname
     * (SafeAddressValidator#requireSafeIfResolvable), up to 100 per request, so unbounded repeated
     * calls meant unbounded outbound DNS traffic at zero cost to the caller. The per-org cap above
     * bounds what actually gets persisted but does nothing to bound the lookup cost of repeatedly
     * submitting batches that mostly fail it.
     */
    @PostMapping("/bulk")
    public ResponseEntity<?> createBulk(
            @Valid @RequestBody BulkCreateTargetsRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        try {
            targetBulkCreateRateLimiter.checkAllowed(principal.userId());
        } catch (TargetBulkCreateRateLimitedException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, String.valueOf(e.retryAfterSeconds()))
                    .build();
        }
        targetBulkCreateRateLimiter.recordRequest(principal.userId());
        int remainingCapacity = maxTargetsPerOrg - targetRepository.countActiveByOrganization(principal.organizationId());
        List<BulkCreateTargetResult> results = new ArrayList<>();
        for (String rawHostname : request.hostnames()) {
            String hostname = rawHostname.trim();
            if (hostname.isEmpty()) {
                continue; // a blank line in a pasted batch isn't a hostname worth reporting on at all
            }
            if (remainingCapacity <= 0) {
                results.add(BulkCreateTargetResult.failure(
                        hostname, "organization has reached its limit of " + maxTargetsPerOrg + " active targets"));
                continue;
            }
            if (!HostnamePattern.PATTERN.matcher(hostname).matches()) {
                results.add(BulkCreateTargetResult.failure(hostname, "must be a valid domain name"));
                continue;
            }
            try {
                SafeAddressValidator.requireSafeIfResolvable(hostname);
            } catch (IOException e) {
                results.add(BulkCreateTargetResult.failure(
                        hostname, "resolves to a private, loopback, or reserved address and cannot be tracked"));
                continue;
            }
            try {
                Target target = targetRepository.insert(principal.organizationId(), hostname, request.targetType());
                results.add(BulkCreateTargetResult.success(hostname, TargetSummary.from(target)));
                remainingCapacity--;
            } catch (DataIntegrityViolationException e) {
                results.add(BulkCreateTargetResult.failure(hostname, "already tracked for this organization"));
            }
        }
        long createdCount = results.stream().filter(BulkCreateTargetResult::created).count();
        if (createdCount > 0) {
            auditLogRepository.record(
                    principal.organizationId(),
                    principal.userId(),
                    principal.email(),
                    "TARGETS_BULK_CREATED",
                    "ORGANIZATION",
                    principal.organizationId().toString(),
                    "count=" + createdCount);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(results);
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
            @Valid @RequestBody UpdateTargetRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Target before = requireOwnedTarget(id, principal);
        targetRepository.updateCadenceAndActive(id, request.scanCadenceSeconds(), request.isActive());
        // Omitted (null) means "this request isn't touching notes" (e.g. the Remove/Restore
        // toggle only ever sends isActive) - a caller that does mean to update notes always sends
        // the field, blank string included, since that's how a save from an emptied textarea
        // looks. See UpdateTargetRequest's own javadoc for why this field alone doesn't follow
        // the plain "null = unchanged" convention scanCadenceSeconds/isActive use.
        if (request.notes() != null) {
            targetRepository.updateNotes(id, request.notes());
        }
        if (request.targetType() != null) {
            targetRepository.updateTargetType(id, request.targetType());
            // A security review found Tier 2 authorization was never revoked when a target's type
            // changed away from OWN - "authorize as OWN, then PATCH the type to COMPETITOR"
            // left authorization_status (and therefore deepScanNow's own AUTHORIZED check) fully
            // intact, bypassing TargetAuthorizationController#authorize's own now-added OWN-only
            // check entirely, since that check only ever runs at authorize time, not retype time.
            // revokeCurrent no-ops safely if there was nothing to revoke, so this is safe to call
            // unconditionally on every non-OWN transition, not just ones that were actually
            // authorized.
            if (!"OWN".equals(request.targetType()) && !request.targetType().equals(before.targetType())) {
                targetAuthorizationRepository.revokeCurrent(id, principal.userId());
                // A security review found this revoked authorization_status but left any
                // already-queued deep-scan jobs sitting in the queue unchanged - see
                // ScanJobRepository#cancelNonTerminalTier2ForTarget's own javadoc.
                scanJobRepository.cancelNonTerminalTier2ForTarget(id, ScanRunService.allTier2ModuleTypes());
            }
        }
        // An audit/reliability review found this endpoint - the only way "Remove"/"Restore" on
        // the Targets page pauses or resumes an entire target's scanning - recorded nothing,
        // despite every other comparably sensitive state change in the app being audited
        // (OrgUserController's role/status changes, RulesCatalogController's enable/disable,
        // this same controller's own delete() below). An admin investigating "why did scanning
        // silently stop for this target" had no audit trail to check. Only the isActive flip is
        // logged, not every cadence/notes edit - that's the one field that actually gates
        // whether monitoring happens at all, the same reasoning that scopes DESTRUCTIVE_ACTIONS
        // on the audit log page to state changes with real operational consequence.
        if (request.isActive() != null && request.isActive() != before.isActive()) {
            auditLogRepository.record(
                    principal.organizationId(),
                    principal.userId(),
                    principal.email(),
                    request.isActive() ? "TARGET_RESTORED" : "TARGET_REMOVED",
                    "TARGET",
                    id.toString(),
                    "hostname=" + before.hostname());
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
