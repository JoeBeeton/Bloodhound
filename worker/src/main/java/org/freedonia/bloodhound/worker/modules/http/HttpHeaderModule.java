package org.freedonia.bloodhound.worker.modules.http;

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
 * Scans the target's root hostname plus its known subdomains (see
 * {@link HostFanOut}) - a target's apex can have no A/AAAA record at all
 * while its real web presence lives entirely on subdomains, so checking only
 * the apex would silently find nothing in that case.
 */
@Component
public class HttpHeaderModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 8;
    private static final long PER_HOST_TIMEOUT_SECONDS = 30;

    private final HttpHeaderFetcher fetcher = new HttpHeaderFetcher();

    @Override
    public String moduleType() {
        return "HTTP_HEADERS";
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
                hostname -> HttpHeaderParser.parse(hostname, fetcher.fetch(hostname)));
        return new ModuleResult(
                result.findings(), Map.of("hostsCovered", result.hostsCovered(), "hostsAttempted", result.hostsAttempted()));
    }
}
