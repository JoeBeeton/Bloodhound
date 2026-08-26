package org.freedonia.bloodhound.worker.modules.dns;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.springframework.stereotype.Component;

/**
 * SPF/DMARC/CAA/DNSSEC/MTA-STS/TLS-RPT/BIMI/DKIM presence checks plus
 * zone-level AXFR/lame-delegation checks - all plain DNS (and, for MTA-STS's
 * policy file, a plain HTTPS GET) queries, no different in kind from what any
 * resolver or browser does. Apex-only by design (unlike HTTP_HEADERS/
 * TLS_ANALYSIS/etc., which fan out across subdomains) since every one of
 * these is a domain-wide concern, not a per-host one.
 */
@Component
public class DnsPostureModule implements ScanModule {

    private final DnsRecordFetcher fetcher = new DnsRecordFetcher();
    private final DnsZoneFetcher zoneFetcher = new DnsZoneFetcher();

    @Override
    public String moduleType() {
        return "DNS_POSTURE";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        try {
            DnsRecords records = fetcher.fetch(context.hostname());
            List<RawFinding> findings = new ArrayList<>(DnsPostureParser.parse(context.hostname(), records));
            findings.addAll(DnsZoneDecisionLogic.decide(zoneFetcher.fetch(context.hostname())));
            return new ModuleResult(findings, Map.of());
        } catch (Exception e) {
            throw new ScanModuleException("DNS posture check failed for " + context.hostname(), e);
        }
    }
}
