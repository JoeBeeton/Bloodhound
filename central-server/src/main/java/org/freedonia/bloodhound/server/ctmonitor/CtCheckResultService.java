package org.freedonia.bloodhound.server.ctmonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.subdomain.SubdomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Handles a completed CT_CHECK job's result: compares the hostnames crt.sh
 * currently reports against what's already on record in the subdomains table
 * (populated by the real SUBDOMAIN_ENUM module - CT_CHECK never writes to
 * that table itself, it only reads from it) and, if any genuinely new
 * certificate-backed hostname turns up, enqueues an immediate full rescan
 * (triggered_by = CT_TRIGGERED) rather than waiting for the target's normal
 * cadence.
 */
@Service
public class CtCheckResultService {

    private static final Logger log = LoggerFactory.getLogger(CtCheckResultService.class);

    private final SubdomainRepository subdomainRepository;
    private final ScanRunService scanRunService;
    private final ScanRunRepository scanRunRepository;

    public CtCheckResultService(
            SubdomainRepository subdomainRepository, ScanRunService scanRunService, ScanRunRepository scanRunRepository) {
        this.subdomainRepository = subdomainRepository;
        this.scanRunService = scanRunService;
        this.scanRunRepository = scanRunRepository;
    }

    public void handle(UUID targetId, Map<String, Object> rawMetadata) {
        List<String> discovered = extractHostnames(rawMetadata);
        Set<String> known = subdomainRepository.findHostnames(targetId);
        if (!hasGenuinelyNewHostname(discovered, known)) {
            return;
        }
        // A reliability review found this was the one caller of createTriggeredScan/
        // createManualScan/createDeepScan that never checked for a scan already in flight -
        // ScanAutoScheduler guards its own cadence-driven scans against exactly this race (see
        // ScanRunRepository#existsRunningForTarget's javadoc), and TargetController's manual
        // triggers gained the same guard earlier this session, but a CT check landing while a
        // manual/scheduled/another CT-triggered scan is already running for the same target could
        // still double-enqueue a full job set - CT checks run every 20 minutes plus once on every
        // startup, so this is a routine window, not a rare edge case.
        if (scanRunRepository.existsRunningForTarget(targetId)) {
            log.debug("CT check found a new hostname for target {} but a scan is already running - skipping", targetId);
            return;
        }
        log.info("CT check found a new certificate-backed hostname for target {} - triggering an immediate rescan", targetId);
        scanRunService.createTriggeredScan(targetId, "CT_TRIGGERED");
    }

    /** Pure - unit-testable without a database. */
    static boolean hasGenuinelyNewHostname(List<String> discovered, Set<String> known) {
        return discovered.stream().anyMatch(h -> !known.contains(h));
    }

    @SuppressWarnings("unchecked")
    static List<String> extractHostnames(Map<String, Object> rawMetadata) {
        if (rawMetadata == null) {
            return List.of();
        }
        Object raw = rawMetadata.get("hostnames");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> hostnames = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                hostnames.add(String.valueOf(item));
            }
        }
        return hostnames;
    }
}
