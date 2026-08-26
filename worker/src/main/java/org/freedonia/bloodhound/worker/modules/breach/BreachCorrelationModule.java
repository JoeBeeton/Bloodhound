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
 * Optional breach-data correlation check, safely inert without an API key
 * so it ships without requiring a paid subscription. Now fully wired for
 * real: {@link HibpBreachCorrelationSource} implements
 * {@link BreachCorrelationSource} against Have I Been Pwned (its own
 * javadoc covers a real limitation worth reading - domain-search only
 * returns data for domains the operator has separately, manually verified
 * ownership of in their HIBP account), "BREACH_CORRELATION" is in
 * ScanRunService.TIER1_MODULE_TYPES so every scan enqueues this job type,
 * and {@code HIBP_API_KEY} is wired through docker-compose.yml. The only
 * remaining step is operator-side and can't be automated: set a real
 * {@code HIBP_API_KEY} in {@code .env} (commented out, empty by default in
 * {@code .env.example}) once a subscription exists. With no key configured
 * - the default, and the common case for most deployments - this module
 * costs nothing: it returns immediately below without making any HTTP call
 * at all.
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
