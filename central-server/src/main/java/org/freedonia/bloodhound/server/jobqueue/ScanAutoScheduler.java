package org.freedonia.bloodhound.server.jobqueue;

import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Reads each active target's next_scan_at/scan_cadence_seconds and enqueues a
 * Tier 1 scan when it's due - the piece that was missing before: targets
 * carried a cadence column since Milestone 2, but nothing ever consulted it,
 * so scanning only ever happened via the manual "Scan now" button. Confirmed
 * by reading the code (no prior @Scheduled task read next_scan_at) before
 * building this, not assumed.
 *
 * <p>Deliberately Tier 1 only - {@link ScanRunService#createTriggeredScan}
 * fans out to TIER1_MODULE_TYPES, never TIER2_MODULE_TYPES. Deep port scan and ZAP
 * active scanning must stay an explicit, one-off human action even for an
 * already-authorized target: authorization means "you may run this", not
 * "run this automatically and repeatedly forever." That boundary is a
 * deliberate safety choice, not an oversight.
 *
 * <p>Poll interval defaults to 5 minutes - frequent enough that a daily
 * cadence fires within 5 minutes of its target time, cheap enough (one query
 * plus a handful of inserts, no network calls) to run that often. A target
 * already mid-run is skipped this cycle rather than double-enqueued; it'll be
 * picked up the following cycle if it's still overdue once free.
 */
@Component
public class ScanAutoScheduler {

    private static final Logger log = LoggerFactory.getLogger(ScanAutoScheduler.class);

    private final TargetRepository targetRepository;
    private final ScanRunRepository scanRunRepository;
    private final ScanRunService scanRunService;

    public ScanAutoScheduler(
            TargetRepository targetRepository, ScanRunRepository scanRunRepository, ScanRunService scanRunService) {
        this.targetRepository = targetRepository;
        this.scanRunRepository = scanRunRepository;
        this.scanRunService = scanRunService;
    }

    @Scheduled(fixedDelayString = "${bloodhound.scheduler.interval-ms:300000}")
    public void sweep() {
        var due = targetRepository.findDueForScan();
        if (due.isEmpty()) {
            return;
        }
        log.info("scan auto-scheduler: {} target(s) due", due.size());
        for (Target target : due) {
            if (scanRunRepository.existsRunningForTarget(target.id())) {
                log.debug("scan auto-scheduler: skipping {} - a run is already in flight", target.hostname());
                continue;
            }
            scanRunService.createTriggeredScan(target.id(), "SCHEDULED");
            Instant next = Instant.now().plus(Duration.ofSeconds(target.scanCadenceSeconds()));
            targetRepository.touchNextScanAt(target.id(), next);
            log.info("scan auto-scheduler: triggered scheduled scan for {}, next at {}", target.hostname(), next);
        }
    }
}
