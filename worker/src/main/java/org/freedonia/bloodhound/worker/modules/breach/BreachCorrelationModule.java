package org.freedonia.bloodhound.worker.modules.breach;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.breach.BreachCorrelationSource.BreachRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Milestone 10 stretch item, built exactly as the plan calls for: plumbing
 * for an optional breach-data correlation check, safely inert by default so
 * it can ship without a paid API subscription. Registered as a ScanModule
 * bean like every other module (so ScanModuleRegistry can dispatch it if
 * asked to), but central-server's ScanRunService never includes
 * "BREACH_CORRELATION" in the Tier 1 module list it fans a scan out to - so
 * this module never actually runs against a real scan unless an operator
 * deliberately wires it in.
 *
 * <p>To enable this module for real: (1) implement BreachCorrelationSource
 * against a real provider (e.g. Have I Been Pwned's domain-search API) as a
 * second @Component - Spring will need a @Primary/@Qualifier if
 * NoOpBreachCorrelationSource should no longer be the one injected here; (2)
 * set the HIBP_API_KEY env var (or whatever the real provider needs) on the
 * worker; (3) add "BREACH_CORRELATION" to ScanRunService.TIER1_MODULE_TYPES
 * on central-server so scans actually enqueue this job type.
 */
@Component
public class BreachCorrelationModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(BreachCorrelationModule.class);

    private final BreachCorrelationSource source;
    private final String apiKey;

    public BreachCorrelationModule(
            BreachCorrelationSource source, @Value("${bloodhound.worker.hibp-api-key:}") String apiKey) {
        this.source = source;
        this.apiKey = apiKey;
    }

    @Override
    public String moduleType() {
        return "BREACH_CORRELATION";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        if (apiKey == null || apiKey.isBlank()) {
            log.debug("breach correlation disabled (no HIBP_API_KEY configured) - skipping {}", context.hostname());
            return new ModuleResult(List.of(), Map.of("enabled", false));
        }
        try {
            List<BreachRecord> records = source.lookup(context.hostname());
            List<RawFinding> findings = records.stream()
                    .map(r -> new RawFinding(
                            "BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH",
                            Severity.MEDIUM,
                            Category.BREACH,
                            "Domain associated with a known data breach",
                            "Email addresses at this domain were found in the breach: " + r.breachName(),
                            context.hostname(),
                            Map.of("breachName", r.breachName(), "breachDate", String.valueOf(r.breachDate()))))
                    .toList();
            return new ModuleResult(findings, Map.of("enabled", true, "recordCount", records.size()));
        } catch (Exception e) {
            throw new ScanModuleException("breach correlation lookup failed for " + context.hostname() + ": " + e.getMessage(), e);
        }
    }
}
