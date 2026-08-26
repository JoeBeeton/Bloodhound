package org.freedonia.bloodhound.server.ctmonitor;

import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Milestone 10 stretch item: certificate-transparency monitoring, independent
 * of a target's normal scan cadence. On a fixed interval, every active target
 * gets one lightweight CT_CHECK job (see CtCheckResultService for what
 * happens with its result) - a plain crt.sh diff-check, not a full
 * SUBDOMAIN_ENUM (no subfinder, no DNS resolution, no dangling-CNAME
 * confirmation), so it's cheap enough to run far more often than a full scan.
 *
 * <p>Interval defaults to 6 hours: still comfortably ahead of the next
 * scheduled full scan (targets default to a 24h cadence) so a newly-issued
 * certificate for a genuinely new subdomain gets noticed and acted on well
 * before then, while keeping crt.sh load - and CT_CHECK's own footprint in
 * the job queue - to a fraction of what a tighter interval produces (crt.sh
 * has shown documented rate-limiting/flakiness repeatedly, see Milestones
 * 4/6a/6b). Configurable via bloodhound.ctmonitor.interval-ms for anyone who
 * wants it tighter or looser.
 */
@Component
public class CtMonitorScheduler {

    private static final Logger log = LoggerFactory.getLogger(CtMonitorScheduler.class);

    private final TargetRepository targetRepository;
    private final ScanRunService scanRunService;

    public CtMonitorScheduler(TargetRepository targetRepository, ScanRunService scanRunService) {
        this.targetRepository = targetRepository;
        this.scanRunService = scanRunService;
    }

    @Scheduled(fixedDelayString = "${bloodhound.ctmonitor.interval-ms:21600000}")
    public void sweep() {
        var activeTargets = targetRepository.findAllActive();
        if (activeTargets.isEmpty()) {
            return;
        }
        log.info("CT monitor sweep: enqueuing CT_CHECK for {} active target(s)", activeTargets.size());
        int skipped = 0;
        for (Target target : activeTargets) {
            if (scanRunService.createCtCheckRun(target.id()).isEmpty()) {
                skipped++;
            }
        }
        if (skipped > 0) {
            log.info("CT monitor sweep: skipped {} target(s) that already had a CT_CHECK queued", skipped);
        }
    }
}
