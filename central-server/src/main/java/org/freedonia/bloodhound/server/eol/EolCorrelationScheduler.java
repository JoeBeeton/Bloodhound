package org.freedonia.bloodhound.server.eol;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.findings.ResultIngestionService;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Correlates fingerprinted technology versions against endoflife.date's release-cycle
 * data - a close structural twin of {@code vuln.VulnerabilityCorrelationScheduler}, same
 * orchestration shape (scheduled tick, shared-across-targets cache, watermark-gated
 * scan_run/notification creation), different signal: a known CVE tells you a specific,
 * already-published vulnerability affects a version; EOL status tells you the version
 * gets NO future patches at all, even for CVEs not yet discovered.
 *
 * <p>Simpler than the CVE scheduler in one respect: endoflife.date is a CDN-served
 * static JSON file with no rate limit (confirmed live while building this - no
 * {@code X-RateLimit-*} headers, generous CDN caching), unlike NVD's ~5-req/30s limit,
 * so there's no inter-call spacing here. The per-tick cap below is normal good-citizen
 * practice, not a requirement.
 *
 * <p>{@code synthesizeFindings} reuses the exact watermark pattern the CVE scheduler
 * already needed to add after a real bug: without comparing a target's newest relevant
 * cache fetch against its last EOL_CORRELATION scan_run, any target with a standing
 * EOL match would get a brand-new scan_run (and "scan completed" notification) every
 * tick, forever - see VulnerabilityCorrelationScheduler's own javadoc for how that
 * played out in practice (200+ scan_runs for one target in two hours).
 */
@Component
public class EolCorrelationScheduler {

    private static final Logger log = LoggerFactory.getLogger(EolCorrelationScheduler.class);

    private static final int MAX_PRODUCTS_PER_TICK = 10;
    private static final Duration CACHE_STALE_AFTER = Duration.ofDays(14);
    private static final int APPROACHING_WINDOW_DAYS = 90;

    private final EndOfLifeClient endOfLifeClient;
    private final EolReleaseCacheRepository cacheRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanRunService scanRunService;
    private final ResultIngestionService resultIngestionService;

    public EolCorrelationScheduler(
            EndOfLifeClient endOfLifeClient,
            EolReleaseCacheRepository cacheRepository,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanRunService scanRunService,
            ResultIngestionService resultIngestionService) {
        this.endOfLifeClient = endOfLifeClient;
        this.cacheRepository = cacheRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanRunService = scanRunService;
        this.resultIngestionService = resultIngestionService;
    }

    @Scheduled(fixedDelayString = "${bloodhound.eol.interval-ms:40000}", initialDelayString = "${bloodhound.eol.initial-delay-ms:25000}")
    public void tick() {
        refreshEolCache();
        synthesizeFindings();
    }

    void refreshEolCache() {
        List<String> pending = cacheRepository.findPendingProducts(
                EolProductSlugMapper.knownTechnologyNames(), CACHE_STALE_AFTER, MAX_PRODUCTS_PER_TICK);
        for (String technologyName : pending) {
            try {
                refreshOne(technologyName);
            } catch (Exception e) {
                log.warn("endoflife.date lookup failed for {}, will retry next cycle: {}", technologyName, e.toString());
            }
        }
    }

    private void refreshOne(String technologyName) throws Exception {
        var slug = EolProductSlugMapper.slugFor(technologyName);
        if (slug.isEmpty()) {
            // Shouldn't happen - findPendingProducts is already restricted to
            // knownTechnologyNames - but recorded as an empty fetch rather than skipped
            // silently, so it doesn't get re-selected every tick if it ever does.
            cacheRepository.replaceForProduct(technologyName, List.of());
            return;
        }
        String raw = endOfLifeClient.fetchRaw(slug.get());
        List<EolRelease> releases = endOfLifeClient.parse(raw);
        cacheRepository.replaceForProduct(technologyName, releases);
        if (!releases.isEmpty()) {
            log.info("EOL correlation: refreshed {} ({} release cycle(s))", technologyName, releases.size());
        }
    }

    void synthesizeFindings() {
        List<EolCandidate> candidates = cacheRepository.findEolCandidates(EolProductSlugMapper.knownTechnologyNames());
        if (candidates.isEmpty()) {
            return;
        }
        Map<String, List<EolRelease>> releasesByProduct = cacheRepository.findAllReleases();
        Map<String, Instant> fetchedAtByProduct = cacheRepository.fetchedAtByProduct();

        Map<UUID, List<FindingPayload>> byTarget = new LinkedHashMap<>();
        Map<UUID, Instant> newestRelevantFetchByTarget = new HashMap<>();
        for (EolCandidate candidate : candidates) {
            List<EolRelease> releases = releasesByProduct.get(candidate.technologyName());
            if (releases == null || releases.isEmpty()) {
                continue; // not yet fetched this tick or ever - nothing to evaluate against yet
            }
            Optional<EolRelease> matched = EolVersionMatcher.match(candidate.version(), releases);
            if (matched.isEmpty()) {
                continue;
            }
            List<FindingPayload> findings = toFindings(candidate, matched.get());
            if (findings.isEmpty()) {
                continue;
            }
            byTarget.computeIfAbsent(candidate.targetId(), id -> new ArrayList<>()).addAll(findings);
            Instant fetchedAt = fetchedAtByProduct.get(candidate.technologyName());
            if (fetchedAt != null) {
                newestRelevantFetchByTarget.merge(
                        candidate.targetId(), fetchedAt, (a, b) -> a.isAfter(b) ? a : b);
            }
        }

        for (Map.Entry<UUID, List<FindingPayload>> entry : byTarget.entrySet()) {
            UUID targetId = entry.getKey();
            Instant newestFetch = newestRelevantFetchByTarget.get(targetId);
            Instant lastSynthesizedAt = scanRunRepository.findLastStartedAt(targetId, "EOL_CORRELATION").orElse(null);
            if (newestFetch != null && lastSynthesizedAt != null && !newestFetch.isAfter(lastSynthesizedAt)) {
                continue;
            }
            ScanRun run = scanRunRepository.insert(targetId, "EOL_CORRELATION", null);
            scanJobRepository.insertComplete(run.id(), targetId, "EOL_CORRELATION");
            resultIngestionService.ingest(run.id(), targetId, "EOL_CORRELATION", null, entry.getValue());
            scanRunService.checkAndCompleteRun(run.id());
        }
    }

    /** Package-private rather than private so this is directly unit-testable without mocking repositories - same reasoning as VulnerabilityCorrelationScheduler#toFindings. At most one finding per candidate: a release is either already EOL, approaching EOL within the window, or neither - never both. */
    List<FindingPayload> toFindings(EolCandidate candidate, EolRelease release) {
        if (release.isEol()) {
            Map<String, Object> evidence = evidenceBase(candidate, release);
            if (release.eolFrom() != null) {
                evidence.put("daysPastEol", ChronoUnit.DAYS.between(release.eolFrom(), today()));
            }
            return List.of(new FindingPayload(
                    "TECH_EOL_SOFTWARE_DETECTED",
                    "MEDIUM",
                    "EXPOSURE",
                    "End-of-life " + candidate.technologyName() + " " + candidate.version() + " in use",
                    "The fingerprinted release cycle (" + release.releaseCycle() + ") of "
                            + candidate.technologyName() + " running on this host has reached end-of-life"
                            + (release.eolFrom() != null ? " (as of " + release.eolFrom() + ")" : "")
                            + " and receives no further security patches from its vendor, even for "
                            + "vulnerabilities not yet discovered.",
                    candidate.hostname(),
                    evidence));
        }
        if (release.eolFrom() != null) {
            long daysUntilEol = ChronoUnit.DAYS.between(today(), release.eolFrom());
            if (daysUntilEol >= 0 && daysUntilEol <= APPROACHING_WINDOW_DAYS) {
                Map<String, Object> evidence = evidenceBase(candidate, release);
                evidence.put("daysUntilEol", daysUntilEol);
                return List.of(new FindingPayload(
                        "TECH_EOL_APPROACHING",
                        "LOW",
                        "EXPOSURE",
                        candidate.technologyName() + " " + candidate.version() + " approaching end-of-life",
                        "The fingerprinted release cycle (" + release.releaseCycle() + ") of "
                                + candidate.technologyName() + " running on this host reaches end-of-life on "
                                + release.eolFrom() + " (" + daysUntilEol + " day(s) from now) - plan an upgrade "
                                + "before then to avoid running unpatched software.",
                        candidate.hostname(),
                        evidence));
            }
        }
        return List.of();
    }

    private static Map<String, Object> evidenceBase(EolCandidate candidate, EolRelease release) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("technology", candidate.technologyName());
        evidence.put("version", candidate.version());
        evidence.put("releaseCycle", release.releaseCycle());
        if (release.eolFrom() != null) {
            evidence.put("eolFrom", release.eolFrom().toString());
        }
        if (release.latestVersionInCycle() != null) {
            evidence.put("latestVersionInCycle", release.latestVersionInCycle());
        }
        return evidence;
    }

    private static LocalDate today() {
        return LocalDate.now(ZoneOffset.UTC);
    }
}
