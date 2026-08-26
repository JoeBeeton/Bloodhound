package org.freedonia.bloodhound.worker.modules.nuclei;

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
 * Tier 2: nuclei template-based scanning against a single host - confirms
 * exploitability against the live target (a real HTTP request/response
 * match) rather than inferring it from a detected version string the way
 * CVE_CORRELATION does passively. Sends real probes/payloads - the same
 * category of intrusiveness as ZAP_ACTIVE_SCAN/PORT_SCAN_DEEP - so this is
 * only ever dispatched via TargetController's authorization-gated
 * POST /targets/{id}/scan/deep (same TIER2_MODULE_TYPES gate), never part
 * of a normal Tier 1 scan run.
 *
 * <p>The internal authorization_status=AUTHORIZED flag is an organizational
 * control, not real-world legal authority over third-party infrastructure -
 * operators must only authorize targets they actually own or have explicit
 * permission to actively scan (same caveat as ZapActiveScanModule's).
 *
 * <p>ScanRunService#createDeepScan dispatches one job per host (root plus
 * known subdomains, capped) rather than one job carrying every host, so
 * this module just scans the single host named in its own job payload
 * ({@link PayloadSubdomains#singleHost}) - multi-host spread happens via the
 * job queue's normal FOR UPDATE SKIP LOCKED claiming, same as the other two
 * Tier 2 modules.
 */
@Component
public class NucleiActiveScanModule implements ScanModule {

    private final NucleiFetcher fetcher = new NucleiFetcher();

    @Override
    public String moduleType() {
        return "NUCLEI_SCAN";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String host = PayloadSubdomains.singleHost(context);
        List<RawFinding> findings = scanOneHost(host);
        return new ModuleResult(findings, Map.of("host", host, "findingCount", findings.size()));
    }

    private List<RawFinding> scanOneHost(String hostname) throws ScanModuleException {
        String jsonl = fetcher.scanJsonLines(hostname);
        List<NucleiFinding> results = NucleiResultParser.parse(jsonl);
        return NucleiFindingMapper.map(results);
    }
}
