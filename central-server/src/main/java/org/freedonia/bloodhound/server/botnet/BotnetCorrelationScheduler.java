package org.freedonia.bloodhound.server.botnet;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
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
 * Correlates every active target's currently-known IP addresses against Feodo Tracker's free
 * botnet-C2 feed - a close structural twin of {@code vuln.VulnerabilityCorrelationScheduler}'s KEV
 * half (a small, free, no-key feed mirrored wholesale), closing a genuine gap this product's rule
 * catalog had: SecurityScorecard/BitSight both have a dedicated "IP Reputation"/"Botnet Infections"
 * risk factor with no prior equivalent here at all.
 *
 * <p>{@code synthesizeFindings} reuses the same watermark pattern every other correlation
 * scheduler in this codebase needs (see VulnerabilityCorrelationScheduler's own javadoc for the
 * real bug - 200+ scan_runs for one target in two hours - this prevents): without comparing the
 * feed's own last-fetched timestamp against a target's last BOTNET_CORRELATION scan_run, any
 * target with a standing match would get a new scan_run/notification every tick, forever.
 */
@Component
public class BotnetCorrelationScheduler {

    private static final Logger log = LoggerFactory.getLogger(BotnetCorrelationScheduler.class);

    // Feodo Tracker is a static, CDN-served file with no documented rate limit, but this still
    // keeps refreshes to a reasonable cadence rather than hitting it every tick - same "good
    // citizen" reasoning as EolCorrelationScheduler's own stale-after window.
    private static final Duration CACHE_STALE_AFTER = Duration.ofHours(6);

    private final FeodoTrackerClient client;
    private final BotnetIpCacheRepository cacheRepository;
    private final TargetIpRepository targetIpRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanRunService scanRunService;
    private final ResultIngestionService resultIngestionService;

    public BotnetCorrelationScheduler(
            FeodoTrackerClient client,
            BotnetIpCacheRepository cacheRepository,
            TargetIpRepository targetIpRepository,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanRunService scanRunService,
            ResultIngestionService resultIngestionService) {
        this.client = client;
        this.cacheRepository = cacheRepository;
        this.targetIpRepository = targetIpRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanRunService = scanRunService;
        this.resultIngestionService = resultIngestionService;
    }

    @Scheduled(fixedDelayString = "${bloodhound.botnet.interval-ms:50000}", initialDelayString = "${bloodhound.botnet.initial-delay-ms:35000}")
    public void tick() {
        refreshCacheIfStale();
        synthesizeFindings();
    }

    void refreshCacheIfStale() {
        try {
            if (!cacheRepository.isStale(CACHE_STALE_AFTER)) {
                return;
            }
            String raw = client.fetchRaw();
            List<BotnetIpEntry> entries = client.parse(raw);
            // Replaced wholesale even when legitimately empty (no "online" entries right now,
            // confirmed a real, normal state live) - same reasoning as KevCatalogRepository/
            // EolReleaseCacheRepository's own fetch-state tracking: this still counts as "freshly
            // checked", not "never fetched", or isStale would re-trigger every tick forever.
            cacheRepository.replaceAll(entries);
            log.info("Refreshed botnet C2 IP cache: {} active entr{}", entries.size(), entries.size() == 1 ? "y" : "ies");
        } catch (Exception e) {
            log.warn("Feodo Tracker refresh failed, will retry next cycle: {}", e.toString());
        }
    }

    void synthesizeFindings() {
        List<TargetIpRepository.Candidate> candidates = targetIpRepository.findAllActiveTargetIps();
        if (candidates.isEmpty()) {
            return;
        }
        Set<String> ips = candidates.stream().map(TargetIpRepository.Candidate::ipAddress).collect(Collectors.toSet());
        Map<String, BotnetIpEntry> matches = cacheRepository.findMatching(ips);
        if (matches.isEmpty()) {
            return;
        }

        Map<UUID, List<FindingPayload>> byTarget = new LinkedHashMap<>();
        for (TargetIpRepository.Candidate candidate : candidates) {
            BotnetIpEntry match = matches.get(candidate.ipAddress());
            if (match == null) {
                continue;
            }
            byTarget.computeIfAbsent(candidate.targetId(), id -> new ArrayList<>()).add(toFinding(candidate, match));
        }
        if (byTarget.isEmpty()) {
            return;
        }

        Instant newestFetch = cacheRepository.fetchedAt();
        for (Map.Entry<UUID, List<FindingPayload>> entry : byTarget.entrySet()) {
            UUID targetId = entry.getKey();
            Instant lastSynthesizedAt = scanRunRepository.findLastStartedAt(targetId, "BOTNET_CORRELATION").orElse(null);
            if (newestFetch != null && lastSynthesizedAt != null && !newestFetch.isAfter(lastSynthesizedAt)) {
                continue;
            }
            ScanRun run = scanRunRepository.insert(targetId, "BOTNET_CORRELATION", null);
            scanJobRepository.insertComplete(run.id(), targetId, "BOTNET_CORRELATION");
            resultIngestionService.ingest(run.id(), targetId, "BOTNET_CORRELATION", null, entry.getValue());
            scanRunService.checkAndCompleteRun(run.id());
        }
    }

    /** Package-private rather than private so this is directly unit-testable without mocking repositories - same reasoning as the other correlation schedulers' own toFindings. */
    FindingPayload toFinding(TargetIpRepository.Candidate candidate, BotnetIpEntry match) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ipAddress", match.ipAddress());
        evidence.put("malware", match.malware());
        if (match.firstSeen() != null) {
            evidence.put("firstSeenAsC2", match.firstSeen().toString());
        }
        evidence.put("source", "abuse.ch Feodo Tracker");
        return new FindingPayload(
                "NETWORK_IP_KNOWN_BOTNET_C2",
                "CRITICAL",
                "NETWORK",
                "Target IP currently listed as active " + match.malware() + " C2 infrastructure",
                "The IP address " + match.ipAddress() + ", currently resolving for " + candidate.hostname()
                        + ", is listed by abuse.ch's Feodo Tracker as an actively responding ("
                        + "\"online\") command-and-control server for " + match.malware() + ". This can mean "
                        + "this host's own infrastructure has been compromised and is running malware C2 "
                        + "software - but cloud IP addresses are also frequently reassigned between "
                        + "unrelated tenants, so a shared-hosting/cloud IP that was previously used by "
                        + "the botnet operator and has since been reassigned to this target is a real, "
                        + "non-malicious possibility worth ruling out first.",
                candidate.hostname(),
                evidence);
    }
}
