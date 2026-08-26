package org.freedonia.bloodhound.worker.modules.tls;

import java.time.Instant;
import java.util.Map;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.HostFanOut;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.stereotype.Component;

/** Scans the target's root hostname plus its known subdomains - see {@link HostFanOut}. */
@Component
public class TlsAnalysisModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 6;
    private static final long PER_HOST_TIMEOUT_SECONDS = 45;

    private final TlsFetcher fetcher = new TlsFetcher();

    @Override
    public String moduleType() {
        return "TLS_ANALYSIS";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        Instant now = Instant.now();
        HostFanOut.Result result = HostFanOut.run(
                context.hostname(),
                PayloadSubdomains.from(context),
                SUBDOMAIN_CAP,
                POOL_SIZE,
                PER_HOST_TIMEOUT_SECONDS,
                hostname -> TlsDecisionLogic.decide(hostname, fetcher.fetch(hostname), now));
        return new ModuleResult(
                result.findings(), Map.of("hostsCovered", result.hostsCovered(), "hostsAttempted", result.hostsAttempted()));
    }
}
