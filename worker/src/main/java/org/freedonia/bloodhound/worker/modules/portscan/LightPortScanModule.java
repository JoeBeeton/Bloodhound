package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
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
 * {@link HostFanOut}. Outer host-level concurrency kept modest (3): each
 * host runs its own 35-port concurrent connect sweep via
 * {@link TcpConnectPortScanner} (60s hard timeout), so the fan-out's
 * per-host timeout here is set comfortably above that as a safety net
 * rather than a binding limit.
 */
@Component
public class LightPortScanModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 3;
    private static final long PER_HOST_TIMEOUT_SECONDS = 100;

    private final TcpConnectPortScanner scanner = new TcpConnectPortScanner();

    @Override
    public String moduleType() {
        return "PORT_SCAN_LIGHT";
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
                this::scanOneHost);
        return new ModuleResult(
                result.findings(), Map.of("hostsCovered", result.hostsCovered(), "hostsAttempted", result.hostsAttempted()));
    }

    private List<RawFinding> scanOneHost(String hostname) throws ScanModuleException {
        return PortScanDecisionLogic.decide(hostname, scanner.scan(hostname));
    }
}
