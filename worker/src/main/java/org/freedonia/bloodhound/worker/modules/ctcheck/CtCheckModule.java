package org.freedonia.bloodhound.worker.modules.ctcheck;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.subdomain.CrtShSource;
import org.springframework.stereotype.Component;

/**
 * Milestone 10 stretch item: the lightweight half of certificate-transparency
 * monitoring. Reuses CrtShSource - the same certificate-transparency lookup
 * SUBDOMAIN_ENUM uses - but does none of that module's other work (no
 * subfinder, no DNS/CNAME resolution, no dangling-CNAME confirmation), so
 * it's cheap enough for CtMonitorScheduler to run far more often than a full
 * scan. Like SUBDOMAIN_ENUM, this module is stateless: it has no idea which
 * of the hostnames it found are already on record for this target, so it
 * just reports the raw list via rawMetadata and leaves the "is anything here
 * genuinely new" comparison to central-server's CtCheckResultService, which
 * is the only place with access to the subdomains table.
 */
@Component
public class CtCheckModule implements ScanModule {

    private final CrtShSource crtShSource;

    public CtCheckModule(CrtShSource crtShSource) {
        this.crtShSource = crtShSource;
    }

    @Override
    public String moduleType() {
        return "CT_CHECK";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        List<String> hostnames;
        try {
            hostnames = crtShSource.discover(context.hostname());
        } catch (Exception e) {
            // crt.sh's documented flakiness (seen repeatedly in prior milestones) means
            // this individual check can fail - it retries via the normal job
            // max_attempts path, and the next scheduled sweep tries again regardless.
            throw new ScanModuleException("CT check failed for " + context.hostname() + ": " + e.getMessage(), e);
        }
        return new ModuleResult(List.of(), Map.of("hostnames", hostnames));
    }
}
