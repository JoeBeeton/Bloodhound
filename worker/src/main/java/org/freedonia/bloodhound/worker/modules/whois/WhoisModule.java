package org.freedonia.bloodhound.worker.modules.whois;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.springframework.stereotype.Component;

@Component
public class WhoisModule implements ScanModule {

    private final WhoisFetcher fetcher = new WhoisFetcher();

    @Override
    public String moduleType() {
        return "WHOIS";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        WhoisFields fields = fetcher.fetch(context.hostname());
        List<RawFinding> findings = WhoisDecisionLogic.decide(context.hostname(), fields, Instant.now());

        // Carried in rawMetadata, not as findings: WHOIS_REGISTRANT_CHANGED needs this target's
        // history, which only central-server's WhoisIngestionService can see (see its class comment).
        Map<String, Object> rawMetadata = new HashMap<>();
        rawMetadata.put("registrar", fields.registrar());
        rawMetadata.put("createdDate", fields.createdDate() == null ? null : fields.createdDate().toString());
        rawMetadata.put("expiryDate", fields.expiryDate() == null ? null : fields.expiryDate().toString());
        rawMetadata.put("registrantOrg", fields.registrantOrg());
        rawMetadata.put("nameServers", fields.nameServers());
        rawMetadata.put("raw", fields.raw());
        rawMetadata.put("viaFallback", fields.viaFallback());

        return new ModuleResult(findings, rawMetadata);
    }
}
