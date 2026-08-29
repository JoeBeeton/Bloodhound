package org.freedonia.bloodhound.worker.modules.bucketbrute;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.subdomain.CloudBucketDecisionLogic;
import org.freedonia.bloodhound.worker.ratelimit.HostnameRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Tier 2: brute-force cloud storage bucket discovery for a target's own
 * brand/root hostname. Only ever dispatched via TargetController's
 * authorization-gated POST /targets/{id}/scan/deep - never part of the
 * normal Tier 1 scan run, same gate as PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN.
 *
 * <p>Deliberately target-scoped, not host-scoped: ScanRunService dispatches
 * this once per target (see TIER2_TARGET_SCOPED_MODULE_TYPES), not fanned
 * out across the target's known subdomains the way PORT_SCAN_DEEP/
 * ZAP_ACTIVE_SCAN/NUCLEI_SCAN are - a guessed bucket name is a property of
 * the organization's brand, not of any one host, so running the identical
 * candidate list once per subdomain would just repeat the same requests for
 * no benefit. context.hostname() (the target's root) is used directly,
 * same as Tier 1's non-fanout modules (DNS_POSTURE, WHOIS, etc.).
 *
 * <p>Candidates come from {@link BucketNameGenerator} (target-hostname stem
 * crossed with common bucket-naming conventions, capped) checked against
 * five S3-API-compatible providers via {@link CloudBucketDecisionLogic}.
 * Rate-limited per *provider* host (see {@link
 * CloudBucketDecisionLogic#rateLimitKeyFor}), not per generated candidate
 * hostname - hundreds of distinct candidate hostnames all resolve to the
 * same handful of shared provider edge networks, so limiting per-candidate
 * would let this module technically satisfy a rate limiter while still
 * bursting far more traffic at one provider than intended.
 *
 * <p>Stateless (this worker has no database access), so "don't re-check the
 * same names every run" is a central-server concern: {@code
 * context.jobPayload()} carries an {@code excludeKeys} list of
 * "candidateName|provider" pairs already checked recently (see
 * ScanRunService#targetScopedPayload / BucketBruteForceCheckRepository) -
 * this module skips those entirely, and reports back every pair it *did*
 * check (regardless of outcome) via rawMetadata's {@code checkedCandidates},
 * which is what lets central-server refresh the "recently checked" record
 * for next time (see BucketBruteForceIngestionService).
 *
 * <p>Same stateless-worker/stateful-central-server split governs the
 * incremental sweep through {@link BucketNameGenerator}'s much larger
 * (18,696-term) wordlist: the payload also carries {@code
 * largeWordlistOffset}/{@code largeWordlistBatchSize} (central-server's
 * per-target cursor - see BucketBruteForceCursorRepository), this module
 * generates just that one slice via {@link
 * BucketNameGenerator#generateFromLargeWordlist} and merges it into the
 * candidate set for this run, and reports back {@code
 * nextLargeWordlistOffset} in rawMetadata for central-server to persist -
 * so coverage of the full list grows a little further with every deep scan
 * rather than restarting from the top each time.
 */
@Component
public class BucketBruteForceModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(BucketBruteForceModule.class);

    private static final int POOL_SIZE = 20;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration PER_CHECK_BUDGET = Duration.ofSeconds(15);
    /** Overall wall-clock backstop, matching every other Tier 2 module's "own its own budget"
     * convention (ZAP: ~12 min, Nuclei: 20 min/host) - not expected to bind under normal
     * rate-limited operation (~200-500 candidates x 5 providers at 12 req/sec/provider is a
     * couple of minutes), a defensive ceiling in case something hangs. */
    private static final Duration OVERALL_BUDGET = Duration.ofMinutes(10);
    /** A bucket-listing response only needs enough to see whether it looks like a directory listing. */
    private static final int BODY_CHAR_CAP = 300_000;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build();

    @Override
    public String moduleType() {
        return "BUCKET_BRUTE_FORCE";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String hostname = context.hostname();
        Set<String> excludeKeys = ExcludeKeys.from(context);

        Set<String> candidateSet = new LinkedHashSet<>(BucketNameGenerator.generate(hostname));
        int largeWordlistOffset = intFromPayload(context, "largeWordlistOffset", 0);
        int largeWordlistBatchSize = intFromPayload(context, "largeWordlistBatchSize", 0);
        BucketNameGenerator.LargeWordlistBatch largeBatch =
                BucketNameGenerator.generateFromLargeWordlist(hostname, largeWordlistOffset, largeWordlistBatchSize);
        candidateSet.addAll(largeBatch.candidates());
        List<String> candidates = new ArrayList<>(candidateSet);

        List<Check> checks = new ArrayList<>();
        for (String candidate : candidates) {
            for (CloudBucketDecisionLogic.Provider provider : CloudBucketDecisionLogic.Provider.values()) {
                Check check = new Check(candidate, provider);
                if (!excludeKeys.contains(check.key())) {
                    checks.add(check);
                }
            }
        }

        Instant deadline = Instant.now().plus(OVERALL_BUDGET);
        List<CheckOutcome> outcomes = runChecks(hostname, checks, deadline);

        List<RawFinding> findings = new ArrayList<>();
        List<Map<String, Object>> checkedCandidates = new ArrayList<>();
        for (CheckOutcome outcome : outcomes) {
            if (outcome.finding() != null) {
                findings.add(outcome.finding());
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("candidateName", outcome.check().candidateName());
            entry.put("provider", outcome.check().provider().name());
            entry.put("wasListable", outcome.wasListable());
            checkedCandidates.add(entry);
        }

        Map<String, Object> rawMetadata = new LinkedHashMap<>();
        rawMetadata.put("candidatesGenerated", candidates.size());
        rawMetadata.put("checksSkippedAlreadyChecked", (candidates.size() * CloudBucketDecisionLogic.Provider.values().length) - checks.size());
        rawMetadata.put("checksAttempted", checks.size());
        rawMetadata.put("checkedCandidates", checkedCandidates);
        // Reported unconditionally (even when largeWordlistBatchSize is 0, where nextOffset just
        // equals the offset we were given) - central-server always persists whatever comes back,
        // so this keeps the cursor's read-modify-write round trip uniform regardless of whether a
        // batch was actually requested this run.
        rawMetadata.put("nextLargeWordlistOffset", largeBatch.nextOffset());
        return new ModuleResult(findings, rawMetadata);
    }

    private record Check(String candidateName, CloudBucketDecisionLogic.Provider provider) {
        /** Matches BucketBruteForceCheckRepository's composite-key format exactly - central-server and
         * this module must agree on it, since the exclusion list only works if both sides build the
         * same key for the same (candidate, provider) pair. */
        String key() {
            return candidateName + "|" + provider.name();
        }
    }

    private record CheckOutcome(Check check, boolean wasListable, RawFinding finding) {}

    private List<CheckOutcome> runChecks(String targetHostname, List<Check> checks, Instant deadline) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, Math.max(1, checks.size())));
        try {
            List<Future<CheckOutcome>> futures = new ArrayList<>();
            for (Check check : checks) {
                futures.add(pool.submit(() -> checkOne(targetHostname, check, deadline)));
            }
            List<CheckOutcome> outcomes = new ArrayList<>();
            for (Future<CheckOutcome> future : futures) {
                try {
                    CheckOutcome outcome = future.get(PER_CHECK_BUDGET.toSeconds(), TimeUnit.SECONDS);
                    if (outcome != null) {
                        outcomes.add(outcome);
                    }
                } catch (Exception ignored) {
                    // Tolerant, same philosophy as CloudBucketChecker: one candidate timing out
                    // shouldn't fail the whole batch. It's simply absent from checkedCandidates
                    // this run - not recorded as checked, so it stays eligible next time.
                }
            }
            return outcomes;
        } finally {
            pool.shutdownNow();
        }
    }

    private CheckOutcome checkOne(String targetHostname, Check check, Instant deadline) {
        if (Instant.now().isAfter(deadline)) {
            return null;
        }
        String url = CloudBucketDecisionLogic.directBucketUrl(check.provider(), check.candidateName());
        HostnameRateLimiter.shared().acquire(CloudBucketDecisionLogic.rateLimitKeyFor(check.provider()));
        CappedResponse response = get(url);
        if (response == null) {
            return null;
        }
        boolean listable = CloudBucketDecisionLogic.isPubliclyListable(response.statusCode(), response.body());
        if (!listable) {
            return new CheckOutcome(check, false, null);
        }
        log.info("brute-forced bucket found publicly listable: {} ({}) for target {}", url, check.provider(), targetHostname);
        RawFinding finding = new RawFinding(
                "EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC",
                Severity.CRITICAL,
                Category.EXPOSURE,
                "Publicly listable cloud storage bucket (discovered via brand-name guessing)",
                "A cloud storage bucket named \"" + check.candidateName() + "\" on " + check.provider()
                        + " - a name related to this organization's brand, not found via any of its own DNS "
                        + "records - allows anyone to list its full contents without authentication.",
                check.candidateName(),
                Map.of("provider", check.provider().name(), "checkUrl", url, "candidateName", check.candidateName()));
        return new CheckOutcome(check, true, finding);
    }

    private record CappedResponse(int statusCode, String body) {}

    private CappedResponse get(String url) {
        try {
            URI uri = URI.create(url);
            // SSRF guard: this URL's host is a guessed bucket-provider hostname, never
            // validated the way a user-submitted target hostname is - see
            // SafeAddressValidator's javadoc. Same guard CloudBucketChecker applies.
            SafeAddressValidator.requireSafeIfResolvable(uri.getHost());
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(REQUEST_TIMEOUT)
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .GET()
                    .build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            return new CappedResponse(response.statusCode(), SafeHttpGet.readCappedUtf8(response.body(), BODY_CHAR_CAP));
        } catch (Exception e) {
            return null;
        }
    }

    /** Tolerant numeric payload read - Jackson deserializes a JSON job payload into {@code
     * Map<String, Object>} with JSON numbers landing as some {@link Number} subtype (Integer for
     * anything in int range, which is all a wordlist offset/batch size ever needs), so this
     * doesn't need to handle String-encoded numbers the way ExcludeKeys tolerates odd list-item
     * shapes; missing/wrong-shaped values just fall back rather than failing the module. */
    private static int intFromPayload(ScanContext context, String key, int fallback) {
        Object raw = context.jobPayload() == null ? null : context.jobPayload().get(key);
        return raw instanceof Number number ? number.intValue() : fallback;
    }

    /** Reads the {@code excludeKeys} list ScanRunService's target-scoped job payload carries -
     * same defensive shape as PayloadSubdomains, tolerant of a missing/malformed payload
     * (falls back to "exclude nothing", i.e. check everything, never to a hard failure). */
    private static final class ExcludeKeys {
        private ExcludeKeys() {}

        static Set<String> from(ScanContext context) {
            Object raw = context.jobPayload() == null ? null : context.jobPayload().get("excludeKeys");
            if (!(raw instanceof List<?> list)) {
                return Set.of();
            }
            Set<String> keys = new java.util.HashSet<>();
            for (Object item : list) {
                if (item != null) {
                    keys.add(String.valueOf(item));
                }
            }
            return keys;
        }
    }
}
