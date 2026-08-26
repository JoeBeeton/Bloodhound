package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.Map;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.HostFanOut;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.stereotype.Component;

/**
 * Scans the target's root hostname plus its known subdomains - see
 * {@link HostFanOut}. Outer host-level concurrency is kept modest (4) since
 * ExposedPathFetcher already runs ~8 probes concurrently per host - at 4
 * hosts in flight that's up to ~32 simultaneous connections, a reasonable
 * ceiling rather than letting host-level and probe-level concurrency
 * multiply unchecked.
 */
@Component
public class ExposedPathModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 4;
    private static final long PER_HOST_TIMEOUT_SECONDS = 40;

    private final ExposedPathFetcher fetcher = new ExposedPathFetcher();

    @Override
    public String moduleType() {
        return "EXPOSURE_CHECKS";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        HostFanOut.Result result = HostFanOut.run(
                context.hostname(),
                PayloadSubdomains.from(context),
                SUBDOMAIN_CAP,
                POOL_SIZE,
                PER_HOST_TIMEOUT_SECONDS,
                hostname -> {
                    ExposedPathFetchResult fetched = fetcher.fetch(hostname);
                    if (ExposedPathDecisionLogic.isHostUnreachable(fetched)) {
                        throw new ScanModuleException(hostname + " is unreachable - exposure probes could not run");
                    }
                    return ExposedPathDecisionLogic.decide(hostname, fetched);
                });
        return new ModuleResult(
                result.findings(),
                Map.of(
                        "probesRun", (ExposedPathFetcher.CATALOG.size() + 1) * result.hostsCovered().size(),
                        "hostsCovered", result.hostsCovered(),
                        "hostsAttempted", result.hostsAttempted()));
    }
}
