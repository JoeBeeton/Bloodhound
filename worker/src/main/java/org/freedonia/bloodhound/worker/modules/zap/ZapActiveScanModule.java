package org.freedonia.bloodhound.worker.modules.zap;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Tier 2: OWASP ZAP spider + active scan against a single host. Sends
 * genuine attack payloads (SQLi/XSS/path-traversal probes etc.) -
 * categorically more intrusive than every other module in this codebase,
 * including the deep port scan. Only ever dispatched via TargetController's
 * authorization-gated POST /targets/{id}/scan/deep (same TIER2_MODULE_TYPES
 * gate as PORT_SCAN_DEEP) - never part of a normal Tier 1 scan run.
 *
 * <p>The internal authorization_status=AUTHORIZED flag is an organizational
 * control, not real-world legal authority over third-party infrastructure -
 * operators must only authorize targets they actually own or have explicit
 * permission to actively scan.
 *
 * <p>ScanRunService#createDeepScan dispatches one job per host (root plus
 * known subdomains, capped) rather than one job carrying every host - so
 * this module just scans the single host named in its own job payload
 * ({@link PayloadSubdomains#singleHost}), and the job queue's normal
 * FOR UPDATE SKIP LOCKED claiming is what spreads a multi-host deep scan
 * across however many workers are actually free, instead of pinning the
 * whole ZAP phase to one worker working through hosts sequentially. Per-host
 * timing is bounded by ZapScanRunner's own 12-minute spider+ascan budget,
 * unchanged by this - there's no separate "overall" budget to manage
 * anymore now that a job is always exactly one host.
 */
@Component
public class ZapActiveScanModule implements ScanModule {

    private final String baseUrl;
    private final String apiKey;

    public ZapActiveScanModule(
            @Value("${bloodhound.worker.zap.base-url:http://zap:8080}") String baseUrl,
            @Value("${bloodhound.worker.zap.api-key:}") String apiKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
    }

    @Override
    public String moduleType() {
        return "ZAP_ACTIVE_SCAN";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        if (apiKey == null || apiKey.isBlank()) {
            throw new ScanModuleException("ZAP_API_KEY is not configured - cannot run an active scan");
        }
        String host = PayloadSubdomains.singleHost(context);
        List<RawFinding> findings = scanOneHost(host);
        return new ModuleResult(findings, Map.of("host", host, "findingCount", findings.size()));
    }

    private List<RawFinding> scanOneHost(String hostname) throws ScanModuleException {
        ZapScanRunner runner = new ZapScanRunner(baseUrl, apiKey);
        String alertsJson = runner.runFullScan(hostname);
        List<ZapAlert> alerts;
        try {
            alerts = ZapAlertParser.parse(alertsJson);
        } catch (IllegalArgumentException e) {
            throw new ScanModuleException("failed to parse ZAP alerts for " + hostname, e);
        }
        return ZapAlertMapper.map(alerts);
    }
}
