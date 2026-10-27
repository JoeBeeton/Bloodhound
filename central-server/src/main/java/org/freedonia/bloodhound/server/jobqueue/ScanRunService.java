package org.freedonia.bloodhound.server.jobqueue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceCheckRepository;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceCursorRepository;
import org.freedonia.bloodhound.server.compound.CompoundRiskAnalysisService;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.notification.NotificationService;
import org.freedonia.bloodhound.server.notification.NotificationType;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotService;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.stereotype.Service;

/**
 * Creates scan runs and decides when one is finished. One scan_jobs row is
 * created per currently-implemented Tier 1 module type - a plain constant
 * list that Milestones 4 and 6 append to as they add modules, rather than a
 * database-driven module registry (no need for that flexibility yet). The
 * run-completion logic below is unchanged by how many jobs a run fans out
 * into.
 */
@Service
public class ScanRunService {

    /**
     * Grows as later milestones add modules. EXPOSURE_CHECKS is deliberately NOT here - a
     * security review found it does far more than its "Tier 1 = passive" billing implied:
     * ExposedPathFetcher attempts a RabbitMQ guest:guest login, POSTs an etcd "dump every key"
     * range request, probes JDWP/Redis/VNC, and fetches credential-shaped paths
     * (/.aws/credentials, /id_rsa, /actuator/heapdump, Kubernetes/Docker/Jenkins control APIs).
     * That ran unconditionally against every COMPETITOR/UNAUTHORIZED target - including real
     * regulated companies with no scanning authorization at all - which is a materially different
     * risk than the genuinely passive checks here (DNS lookups, reading response headers, a plain
     * TCP connect scan). Moved to {@link #TIER2_MODULE_TYPES} below, gated the same way
     * PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN already are: only ever dispatched by {@link
     * #createDeepScan} after the caller has confirmed authorization_status = AUTHORIZED.
     */
    private static final List<String> TIER1_MODULE_TYPES = List.of(
            "DNS_POSTURE",
            "HTTP_HEADERS",
            "TLS_ANALYSIS",
            "SUBDOMAIN_ENUM",
            "PORT_SCAN_LIGHT",
            "WHOIS",
            "TECH_FINGERPRINT",
            "TYPOSQUAT_MONITOR",
            "APP_STORE_MONITOR",
            "BREACH_CORRELATION",
            "DOCUMENT_METADATA");

    /**
     * Module types that scan a target's root hostname plus its known
     * subdomains, not just the bare apex - the worker has no database access
     * of its own to learn a target's already-discovered subdomains (unlike
     * SUBDOMAIN_ENUM, which is the one discovering them), so central-server
     * hands over a capped hostname list in the job payload instead (see
     * {@link #buildSubdomainPayload}). This matters because a target's apex
     * can legitimately have no A/AAAA record at all while its real web
     * presence lives entirely on subdomains - scanning only the apex in that
     * case finds nothing. DNS_POSTURE and WHOIS are deliberately excluded:
     * SPF/DMARC/DNSSEC and domain registration are domain-wide concerns, not
     * per-host, so fanning them out would just repeat identical results.
     * SUBDOMAIN_ENUM is excluded because it's the source of the list, not a
     * consumer of it. TYPOSQUAT_MONITOR and APP_STORE_MONITOR are excluded for the same
     * reason: lookalike domains/apps are of the brand/root domain itself, not of each
     * individual subdomain, so both always operate on just the target's own
     * hostname regardless of this list. BREACH_CORRELATION is excluded for
     * the same reason as DNS_POSTURE/WHOIS: breached credentials are tied to
     * an email address at the domain itself ("user@example.com"), not to
     * any particular subdomain, so it's a once-per-target check too.
     * DOCUMENT_METADATA is included: a linked handbook/whitepaper leaking
     * author info is just as likely to live on a subdomain's homepage as on
     * the apex. EXPOSURE_CHECKS is no longer here - see its own comment on
     * {@link #TIER1_MODULE_TYPES}; it fans out per-host under {@link #TIER2_MODULE_TYPES} now.
     */
    private static final List<String> SUBDOMAIN_FANOUT_MODULE_TYPES = List.of(
            "HTTP_HEADERS", "TLS_ANALYSIS", "PORT_SCAN_LIGHT", "TECH_FINGERPRINT", "DOCUMENT_METADATA");

    /**
     * Capped because a target can have hundreds of subdomains (e.g.
     * wikipedia.org's real subfinder results) - scanning all of them with
     * every fan-out module would turn one scan into an unbounded number of
     * HTTP fetches, TLS handshakes, and port-scan processes. The target's own
     * root hostname is always scanned regardless of this cap.
     */
    private static final int TIER1_SUBDOMAIN_CAP = 40;

    /**
     * Tier 2 active-scan module types - deliberately never dispatched by
     * {@link #createManualScan}/{@link #createTriggeredScan}. Only {@link
     * #createDeepScan} fans out to these, and only after the caller
     * (TargetController) has confirmed targets.authorization_status =
     * 'AUTHORIZED' - see TargetAuthorizationController. PORT_SCAN_DEEP,
     * ZAP_ACTIVE_SCAN, and NUCLEI_SCAN all scan known subdomains, not just
     * the apex, per the same rationale as {@link #SUBDOMAIN_FANOUT_MODULE_TYPES}. EXPOSURE_CHECKS
     * joined this list after a security review found it was never actually passive - see the
     * comment on {@link #TIER1_MODULE_TYPES}. SUBDOMAIN_TAKEOVER_CHECK joined for the same
     * reason: a later security/legal review found SUBDOMAIN_ENUM's dangling-CNAME/cloud-bucket/
     * NS-takeover confirmation checks make an active HTTP GET or direct-to-nameserver DNS query
     * against whatever a subdomain's CNAME or NS records point at, not plain passive discovery -
     * see SubdomainTakeoverCheckModule's own javadoc.
     */
    private static final List<String> TIER2_MODULE_TYPES = List.of(
            "PORT_SCAN_DEEP", "ZAP_ACTIVE_SCAN", "NUCLEI_SCAN", "EXPOSURE_CHECKS", "SUBDOMAIN_TAKEOVER_CHECK");

    /**
     * Tier 2 module types that are properties of the target's *brand* or of its DNS zone as a
     * whole, not of any one host - dispatched once per target, never fanned out across
     * {@link #TIER2_SUBDOMAIN_CAP} hosts the way {@link #TIER2_MODULE_TYPES} is. BUCKET_BRUTE_FORCE:
     * a guessed bucket name isn't tied to any particular subdomain, so running the identical
     * candidate list once per host (up to 16 times) would just repeat the same requests for no
     * benefit - the same "domain-wide, not per-host" reasoning that excludes DNS_POSTURE/WHOIS
     * from {@link #SUBDOMAIN_FANOUT_MODULE_TYPES} above. DNS_ZONE_EXPLOIT joined for the same
     * domain-wide reasoning as DNS_POSTURE itself: a domain's nameservers aren't a per-host
     * concern either - see DnsZoneExploitModule's own javadoc for why its AXFR/open-resolver
     * checks moved out of Tier 1's DNS_POSTURE into here.
     */
    private static final List<String> TIER2_TARGET_SCOPED_MODULE_TYPES =
            List.of("BUCKET_BRUTE_FORCE", "DNS_ZONE_EXPLOIT");

    /**
     * Single source of truth for "which module types count as a deep scan" - lets other classes
     * (e.g. TargetController, composing the Targets list' "last scan: regular/deep" display) ask
     * the question without duplicating TIER2_MODULE_TYPES/TIER2_TARGET_SCOPED_MODULE_TYPES, which
     * stay private here.
     */
    public static List<String> allTier2ModuleTypes() {
        return java.util.stream.Stream.concat(TIER2_MODULE_TYPES.stream(), TIER2_TARGET_SCOPED_MODULE_TYPES.stream())
                .toList();
    }

    /**
     * Single source of truth for "which module types a regular/scheduled scan fans out to" - lets
     * TargetController estimate a not-yet-started scan's duration (see ScanEtaEstimator) against
     * the exact set {@link #insertTier1Jobs} actually dispatches, without duplicating
     * {@link #TIER1_MODULE_TYPES}, which stays private here.
     */
    public static List<String> allTier1ModuleTypes() {
        return TIER1_MODULE_TYPES;
    }

    /**
     * How recently a (candidate, provider) pair must have been checked to be excluded from the
     * next BUCKET_BRUTE_FORCE job's payload - long enough that re-running a deep scan doesn't
     * re-issue the same few hundred requests against AWS/GCS/etc. every time, short enough that
     * a bucket created or made public after the last check is still eventually found.
     */
    private static final Duration BUCKET_BRUTE_FORCE_RECHECK_COOLDOWN = Duration.ofDays(14);

    /**
     * How many terms of BucketNameGenerator's large (18,696-term) wordlist a single deep scan
     * consumes before the cursor advances - crossed with hyphen/no-hyphen joins and 5 providers,
     * that's up to 1,500 extra checks per run. Combined with the always-included small-wordlist
     * baseline (~400 candidates x 5 providers, mostly cooldown-excluded after the first pass),
     * this stays comfortably inside BucketBruteForceModule's 10-minute overall budget even before
     * accounting for rate-limiting headroom (live-verified: ~810 checks completed in ~89s). At this
     * rate a full pass through the large wordlist takes roughly 18,696 / 150 ≈ 125 deep scans for
     * one target - a deliberate slow burn, not something meant to finish quickly; coverage widens
     * with every deep scan the user actually runs rather than trying to front-load it into one.
     */
    private static final int BUCKET_BRUTE_FORCE_LARGE_WORDLIST_BATCH_SIZE = 150;

    /**
     * Meaningfully tighter than {@link #TIER1_SUBDOMAIN_CAP}: a single deep
     * port scan or ZAP active scan against ONE host can already take several
     * minutes, so a target with dozens of subdomains would turn a deep scan
     * into a multi-hour job at the Tier 1 cap. Both Tier 2 modules also
     * apply their own overall wall-clock budget on top of this cap (see
     * DeepPortScanModule/ZapActiveScanModule), so worst-case duration stays
     * predictable even at this cap.
     */
    private static final int TIER2_SUBDOMAIN_CAP = 15;

    /**
     * Exposes {@link #TIER2_SUBDOMAIN_CAP} so TargetController can reproduce
     * {@link #createDeepScan}'s exact host count (apex + up to this many subdomains) when
     * estimating a not-yet-run deep scan's duration, without duplicating the constant.
     */
    public static int tier2SubdomainCap() {
        return TIER2_SUBDOMAIN_CAP;
    }

    /**
     * Tier 2 module types that fan out per-host (one job per selected host) - see
     * {@link #createDeepScan}. Distinct from {@link #allTier2ModuleTypes()}, which also includes
     * the target-scoped {@link #TIER2_TARGET_SCOPED_MODULE_TYPES}: a duration estimate needs to
     * know which types to multiply by host count and which run exactly once.
     */
    public static List<String> tier2FanoutModuleTypes() {
        return TIER2_MODULE_TYPES;
    }

    /** The complement of {@link #tier2FanoutModuleTypes()} within {@link #allTier2ModuleTypes()} - dispatched once per target, never multiplied by host count. */
    public static List<String> tier2TargetScopedModuleTypes() {
        return TIER2_TARGET_SCOPED_MODULE_TYPES;
    }

    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScoreSnapshotService scoreSnapshotService;
    private final CompoundRiskAnalysisService compoundRiskAnalysisService;
    private final SubdomainRepository subdomainRepository;
    private final ObjectMapper objectMapper;
    private final TargetRepository targetRepository;
    private final FindingRepository findingRepository;
    private final NotificationService notificationService;
    private final BucketBruteForceCheckRepository bucketBruteForceCheckRepository;
    private final BucketBruteForceCursorRepository bucketBruteForceCursorRepository;

    public ScanRunService(
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScoreSnapshotService scoreSnapshotService,
            CompoundRiskAnalysisService compoundRiskAnalysisService,
            SubdomainRepository subdomainRepository,
            ObjectMapper objectMapper,
            TargetRepository targetRepository,
            FindingRepository findingRepository,
            NotificationService notificationService,
            BucketBruteForceCheckRepository bucketBruteForceCheckRepository,
            BucketBruteForceCursorRepository bucketBruteForceCursorRepository) {
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scoreSnapshotService = scoreSnapshotService;
        this.compoundRiskAnalysisService = compoundRiskAnalysisService;
        this.subdomainRepository = subdomainRepository;
        this.objectMapper = objectMapper;
        this.targetRepository = targetRepository;
        this.findingRepository = findingRepository;
        this.notificationService = notificationService;
        this.bucketBruteForceCheckRepository = bucketBruteForceCheckRepository;
        this.bucketBruteForceCursorRepository = bucketBruteForceCursorRepository;
    }

    public ScanRun createManualScan(UUID targetId, UUID triggeredByUserId) {
        ScanRun run = scanRunRepository.insert(targetId, "MANUAL", triggeredByUserId);
        insertTier1Jobs(run.id(), targetId);
        notifyScanStarted(run);
        return run;
    }

    /**
     * A full Tier 1 scan run with no human trigger - used by
     * {@link org.freedonia.bloodhound.server.ctmonitor.CtCheckResultService}
     * when a CT_CHECK job finds a certificate-backed hostname not already on
     * record, so the target gets rescanned immediately rather than waiting
     * for its next cadence-driven scan.
     */
    public ScanRun createTriggeredScan(UUID targetId, String triggeredBy) {
        ScanRun run = scanRunRepository.insert(targetId, triggeredBy, null);
        insertTier1Jobs(run.id(), targetId);
        notifyScanStarted(run);
        return run;
    }

    private void insertTier1Jobs(UUID scanRunId, UUID targetId) {
        FanoutSelection fanout = buildSubdomainPayload(targetId, TIER1_SUBDOMAIN_CAP);
        TIER1_MODULE_TYPES.forEach(moduleType -> scanJobRepository.insert(
                scanRunId,
                targetId,
                moduleType,
                SUBDOMAIN_FANOUT_MODULE_TYPES.contains(moduleType) ? fanout.payloadJson() : "{}"));
        // Only after every job above is actually inserted: if insert() threw
        // partway through the forEach, execution never reaches this line, so
        // a hostname is never marked scanned for work that didn't get
        // queued. No @Transactional wrapping needed for that guarantee - it
        // falls out of ordinary sequential execution, same as the rest of
        // this class already relies on for its job-insertion loops.
        subdomainRepository.markScanned(targetId, fanout.selectedHostnames());
    }

    /**
     * One DB read of the target's known subdomains, reused across every
     * fan-out module in a run rather than queried once per module. The
     * hostname list is ordered/capped by SubdomainRepository itself (see
     * findHostnamesForFanout) so subdomains never yet covered take priority
     * over ones already scanned - not truncated here from an arbitrary,
     * unordered collection as this used to do.
     */
    private FanoutSelection buildSubdomainPayload(UUID targetId, int cap) {
        List<String> capped = subdomainRepository.findHostnamesForFanout(targetId, cap);
        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(Map.of("subdomains", capped));
        } catch (Exception e) {
            // Falls back to "just the root hostname" (every fan-out module
            // always scans context.hostname() regardless of payload) rather
            // than failing job creation over a serialization problem in an
            // optional list.
            payloadJson = "{}";
        }
        return new FanoutSelection(payloadJson, capped);
    }

    private record FanoutSelection(String payloadJson, List<String> selectedHostnames) {}

    /**
     * A Tier 2 active-scan run. Callers MUST have already verified the
     * target's authorization_status is AUTHORIZED (this method does not
     * re-check it - see TargetController#deepScanNow) so that check stays a
     * single, auditable place rather than being duplicated per module type
     * as Tier 2 grows.
     *
     * <p>Also queues every Tier 1 job (via {@link #insertTier1Jobs}, the exact same call
     * {@link #createManualScan} makes) - a product review found "Deep scan" was previously a
     * Tier-2-*only* run, silently skipping the regular Tier 1 checks (DNS posture, headers, TLS,
     * WHOIS, breach correlation, etc.) entirely. That's surprising: "deep" reads as "everything a
     * regular scan does, plus more," not "instead of." A user who only ever deep-scans an
     * authorized target should never end up with LESS coverage than one who only ever runs
     * regular scans.
     *
     * <p>One {@code scan_jobs} row per (module type, host) pair for the Tier 2 modules -
     * deliberately NOT one row per module type carrying every host in its payload, which is how
     * this used to work and how {@link #insertTier1Jobs} still works for Tier 1. That approach
     * pinned an entire deep scan's ZAP/port-scan phase to whichever single worker claimed the one
     * job, no matter how many other workers sat idle, since the fan-out across hosts happened
     * *inside* that one job rather than as separate claimable units. Real observed behavior: 3
     * workers available, only 1-2 ever busy during a deep scan. Splitting per host lets the
     * existing FOR UPDATE SKIP LOCKED claim logic - built exactly for this - spread the work
     * across every idle worker instead. Tier 1 doesn't need this: its per-host work is seconds,
     * not minutes, so pinning one worker to one module's whole fan-out isn't the same kind of
     * waste - and it stays exactly 11 extra jobs regardless of subdomain count, a small, bounded
     * addition to a deep scan's total job count.
     */
    public ScanRun createDeepScan(UUID targetId, UUID triggeredByUserId) {
        ScanRun run = scanRunRepository.insert(targetId, "MANUAL", triggeredByUserId);
        insertTier1Jobs(run.id(), targetId);
        Target target = targetRepository.findById(targetId).orElseThrow();
        FanoutSelection fanout = buildSubdomainPayload(targetId, TIER2_SUBDOMAIN_CAP);
        List<String> hosts = new java.util.ArrayList<>();
        hosts.add(target.hostname());
        hosts.addAll(fanout.selectedHostnames());
        TIER2_MODULE_TYPES.forEach(moduleType ->
                hosts.forEach(host -> scanJobRepository.insert(run.id(), targetId, moduleType, hostPayload(host))));
        TIER2_TARGET_SCOPED_MODULE_TYPES.forEach(moduleType ->
                scanJobRepository.insert(run.id(), targetId, moduleType, targetScopedPayload(moduleType, targetId)));
        subdomainRepository.markScanned(targetId, fanout.selectedHostnames());
        notifyScanStarted(run);
        return run;
    }

    /** A single-host job payload - {@code {"host": "..."}}, the per-job counterpart to {@link #buildSubdomainPayload}'s multi-host {@code {"subdomains": [...]}}. */
    private String hostPayload(String host) {
        try {
            return objectMapper.writeValueAsString(Map.of("host", host));
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize a plain single-hostname job payload", e);
        }
    }

    /**
     * The payload for a {@link #TIER2_TARGET_SCOPED_MODULE_TYPES} job - no host at all (every
     * module in that list reads {@code context.hostname()} directly, the target's own root).
     * BUCKET_BRUTE_FORCE is the one module type here that needs real payload data: two
     * independent pieces of "don't redo work you already did" state - an exclusion list of
     * "candidateName|provider" keys already checked within {@link
     * #BUCKET_BRUTE_FORCE_RECHECK_COOLDOWN} (see BucketBruteForceCheckRepository), and where this
     * target's sweep through BucketNameGenerator's large wordlist left off last time (see
     * BucketBruteForceCursorRepository/{@link #BUCKET_BRUTE_FORCE_LARGE_WORDLIST_BATCH_SIZE}).
     * Every other target-scoped module type (DNS_ZONE_EXPLOIT) gets a plain empty payload -
     * building BUCKET_BRUTE_FORCE's own cooldown/cursor lookups for a module that has no use for
     * them would just be wasted DB queries.
     */
    private String targetScopedPayload(String moduleType, UUID targetId) {
        if (!"BUCKET_BRUTE_FORCE".equals(moduleType)) {
            return "{}";
        }
        Set<String> excludeKeys = bucketBruteForceCheckRepository.findRecentlyCheckedKeys(
                targetId, Instant.now().minus(BUCKET_BRUTE_FORCE_RECHECK_COOLDOWN));
        int largeWordlistOffset = bucketBruteForceCursorRepository.currentPosition(targetId);
        try {
            return objectMapper.writeValueAsString(Map.of(
                    "excludeKeys", excludeKeys,
                    "largeWordlistOffset", largeWordlistOffset,
                    "largeWordlistBatchSize", BUCKET_BRUTE_FORCE_LARGE_WORDLIST_BATCH_SIZE));
        } catch (Exception e) {
            // Falls back to "check everything, from the top of the large wordlist" rather than
            // failing job creation over a serialization problem in optional dedup/cursor state -
            // worse for politeness this one run, never worse for correctness.
            return "{}";
        }
    }

    /**
     * Fires SCAN_STARTED. Never called by {@link #createCtCheckRun} - CtMonitorScheduler's
     * lightweight crt.sh-diff sweeps run every ~20 minutes per target (plus once on every
     * app startup), so notifying on those would flood a user with "scan started" every 20
     * minutes for every target. The real, meaningful event a CT_CHECK can cause -
     * discovering a genuinely new hostname and triggering a full rescan - already goes
     * through {@link #createTriggeredScan} (triggeredBy="CT_TRIGGERED"), which DOES notify.
     */
    private void notifyScanStarted(ScanRun run) {
        Target target = targetRepository.findById(run.targetId()).orElse(null);
        if (target == null) {
            return;
        }
        notificationService.notify(
                target.organizationId(),
                NotificationType.SCAN_STARTED,
                "INFO",
                "Scan started: " + target.hostname(),
                "A scan was started for " + target.hostname() + ".",
                target.id(),
                run.id());
    }

    /**
     * A single-job scan_run wrapping just a CT_CHECK job - deliberately
     * outside TIER1_MODULE_TYPES (it's dispatched only by
     * CtMonitorScheduler's own schedule, never as part of a normal/manual
     * scan). Still goes through the ordinary scan_run completion path (see
     * checkAndCompleteRun), so it produces one extra, harmless score_snapshot
     * per check - CT_CHECK never changes findings, so that snapshot is
     * always identical to the one before it. Accepted as simpler than adding
     * a "lightweight run" flag to skip scoring for this one run type.
     *
     * <p>Skips creating a new run/job entirely - returns empty - if this
     * target already has a not-yet-finished CT_CHECK sitting in the queue
     * (PENDING/CLAIMED/RUNNING). CtMonitorScheduler fires on its own fixed
     * wall-clock interval regardless of whether the queue has caught up on
     * the previous sweep (worker capacity contention, a central-server
     * restart re-triggering @Scheduled's immediate first run, etc.), and
     * without this guard that piles up duplicate CT_CHECK jobs for the same
     * target rather than just widening the gap until the next check - purely
     * wasted queue/worker/crt.sh load for a module that gains nothing from
     * running twice before the first attempt has even finished.
     */
    public Optional<ScanRun> createCtCheckRun(UUID targetId) {
        if (scanJobRepository.existsNonTerminal(targetId, "CT_CHECK")) {
            return Optional.empty();
        }
        ScanRun run = scanRunRepository.insert(targetId, "CT_CHECK", null);
        scanJobRepository.insert(run.id(), targetId, "CT_CHECK", "{}");
        return Optional.of(run);
    }

    /**
     * If every job for this run has reached a terminal state, marks the run
     * COMPLETE (all succeeded) or PARTIAL_FAILURE (at least one FAILED), then
     * computes a score snapshot from the target's currently-open findings.
     * Safe to call redundantly - ScanRunRepository#markComplete only applies
     * to a still-RUNNING run and reports whether *this* call was the one that
     * applied it, so scoring runs exactly once per run even if two jobs
     * finish at the same moment and both reach this check. Scoring happens
     * for PARTIAL_FAILURE too (using whatever findings did get ingested, plus
     * any still open from earlier runs) - partial data is still real signal,
     * and a target's open-findings set never goes fully empty just because
     * one module job failed this time.
     *
     * <p>Compound-risk analysis (see CompoundRiskAnalysisService) runs first,
     * so a snapshot's finding_counts reflect this run's compound findings
     * too - not just for CT_CHECK/etc. runs specially, uniformly for every
     * completed run, same "simpler than a per-run-type flag" call already
     * made for scoring itself above.
     */
    public void checkAndCompleteRun(UUID scanRunId) {
        List<ScanJob> jobs = scanJobRepository.findByScanRunId(scanRunId);
        boolean anyPending = jobs.stream().anyMatch(j -> !isTerminal(j.status()));
        if (anyPending || jobs.isEmpty()) {
            return;
        }
        boolean anyFailed = jobs.stream().anyMatch(j -> "FAILED".equals(j.status()));
        boolean applied = scanRunRepository.markComplete(scanRunId, anyFailed ? "PARTIAL_FAILURE" : "COMPLETE");
        if (applied) {
            UUID targetId = jobs.get(0).targetId();
            compoundRiskAnalysisService.analyzeAndIngest(targetId, scanRunId);
            scoreSnapshotService.computeAndPersist(targetId, scanRunId);
            notifyScanCompleted(scanRunId, targetId, anyFailed);
        }
    }

    /** See {@link #notifyScanStarted} for why CT_CHECK runs are excluded here too. */
    private void notifyScanCompleted(UUID scanRunId, UUID targetId, boolean anyFailed) {
        ScanRun run = scanRunRepository.findById(scanRunId).orElse(null);
        Target target = targetRepository.findById(targetId).orElse(null);
        if (run == null || target == null || "CT_CHECK".equals(run.triggeredBy())) {
            return;
        }
        if (anyFailed) {
            notificationService.notify(
                    target.organizationId(),
                    NotificationType.SCAN_FAILED,
                    "HIGH",
                    "Scan issues: " + target.hostname(),
                    "One or more modules failed during a scan of " + target.hostname() + ".",
                    target.id(),
                    scanRunId);
        } else {
            notificationService.notify(
                    target.organizationId(),
                    NotificationType.SCAN_COMPLETED,
                    "INFO",
                    "Scan completed: " + target.hostname(),
                    "A scan of " + target.hostname() + " finished successfully.",
                    target.id(),
                    scanRunId);
        }

        int newFindings = findingRepository.countNewSince(scanRunId);
        if (newFindings > 0) {
            notificationService.notify(
                    target.organizationId(),
                    NotificationType.NEW_FINDINGS,
                    newFindings >= 5 ? "HIGH" : "MEDIUM",
                    newFindings + " new finding" + (newFindings == 1 ? "" : "s") + " on " + target.hostname(),
                    newFindings + " new finding" + (newFindings == 1 ? "" : "s")
                            + " (Medium severity or higher) discovered on " + target.hostname() + ".",
                    target.id(),
                    scanRunId);
        }

        int newSubdomains = subdomainRepository.countNewSince(targetId, run.startedAt());
        if (newSubdomains > 0) {
            notificationService.notify(
                    target.organizationId(),
                    NotificationType.NEW_SUBDOMAINS,
                    "INFO",
                    newSubdomains + " new subdomain" + (newSubdomains == 1 ? "" : "s") + " on " + target.hostname(),
                    newSubdomains + " new subdomain" + (newSubdomains == 1 ? "" : "s")
                            + " discovered on " + target.hostname() + ".",
                    target.id(),
                    scanRunId);
        }
    }

    /**
     * Stops a RUNNING scan from progressing further - a product review found CANCELLED already
     * treated as a full-fledged terminal status everywhere (ScanEtaEstimator, this class's own
     * {@link #isTerminal}, the Scans page's status filter/badge), but nothing anywhere could ever
     * actually produce one - there was no way for a user to cancel a scan they'd started by
     * mistake or that was stuck.
     *
     * <p>Only PENDING/CLAIMED/RUNNING jobs move to CANCELLED (see {@link
     * ScanJobRepository#cancelNonTerminalForRun}) - a job a worker already claimed keeps running
     * to completion rather than being forcibly interrupted (this pull-based queue has no
     * mechanism for that). Its eventual result report can't flip the job back to COMPLETE
     * (ScanJobRepository#complete/#fail both guard on CLAIMED/RUNNING, which a CANCELLED job no
     * longer satisfies) or reopen the run (markComplete below only ever applies once), though a
     * handful of findings the module had already gathered may still land in the DB before that
     * report is rejected - JobLifecycleService#result ingests before checking the job's status.
     * Accepted as the same kind of benign raciness the lease reaper already tolerates elsewhere in
     * this queue, not worth adding an extra guard to a code path this narrow. No score snapshot is
     * computed for a cancelled run, unlike {@link #checkAndCompleteRun} - a deliberately-stopped
     * scan has incomplete data, not a real result to score against.
     *
     * <p>No-op (returns false) if the run isn't currently RUNNING - matches {@link
     * ScanRunRepository#markComplete}'s own "applies exactly once" guarantee, so a caller can't
     * cancel an already-finished run out from under a concurrent completion.
     */
    public boolean cancel(UUID runId) {
        boolean applied = scanRunRepository.markComplete(runId, "CANCELLED");
        if (applied) {
            scanJobRepository.cancelNonTerminalForRun(runId);
        }
        return applied;
    }

    private static boolean isTerminal(String status) {
        return status.equals("COMPLETE")
                || status.equals("FAILED")
                || status.equals("CANCELLED")
                || status.equals("UNREACHABLE");
    }
}
