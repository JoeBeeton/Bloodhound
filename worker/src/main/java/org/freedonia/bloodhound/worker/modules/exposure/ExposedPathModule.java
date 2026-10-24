package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.stereotype.Component;

/**
 * Tier 2: a single host's worth of exposure probes. Only ever dispatched via
 * TargetController's authorization-gated deep scan - never part of the
 * normal Tier 1 scan run.
 *
 * <p>Was Tier 1 until a security review found it ran far more than passive
 * recon unconditionally against every target, including unauthorized
 * COMPETITOR/WATCHLIST ones: ExposedPathFetcher attempts a RabbitMQ
 * guest:guest login, POSTs an etcd "dump every key" range request, probes
 * JDWP/Redis/VNC, and fetches credential-shaped paths
 * (/.aws/credentials, /id_rsa, /actuator/heapdump, Kubernetes/Docker/Jenkins
 * control APIs) - see ScanRunService's own comment on TIER1_MODULE_TYPES.
 * Moved to the same one-host-per-job dispatch scheme PORT_SCAN_DEEP already
 * uses ({@link PayloadSubdomains#singleHost}) rather than the old
 * {@code HostFanOut}-based "every known subdomain in one job" shape -
 * fanning out across hosts now happens via the job queue (one claimable job
 * per host), same reasoning as DeepPortScanModule's own comment.
 */
@Component
public class ExposedPathModule implements ScanModule {

    private final ExposedPathFetcher fetcher = new ExposedPathFetcher();

    @Override
    public String moduleType() {
        return "EXPOSURE_CHECKS";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String hostname = PayloadSubdomains.singleHost(context);
        ExposedPathFetchResult fetched = fetcher.fetch(hostname);
        if (ExposedPathDecisionLogic.isHostUnreachable(fetched)) {
            throw new ScanModuleException(hostname + " is unreachable - exposure probes could not run");
        }
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(hostname, fetched);
        return new ModuleResult(
                findings,
                Map.of(
                        "host",
                        hostname,
                        // +2, not +1: the baseline probe plus the homepage fetch EXPOSURE_JS_SOURCE_MAP
                        // needs (its own variable number of .map probes isn't counted here, same
                        // approximation this field already accepted for the Redis raw-socket probe).
                        "probesRun",
                        ExposedPathFetcher.CATALOG.size() + 2,
                        "findingCount",
                        findings.size()));
    }
}
