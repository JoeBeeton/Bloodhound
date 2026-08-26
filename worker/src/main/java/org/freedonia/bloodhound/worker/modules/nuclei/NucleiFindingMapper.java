package org.freedonia.bloodhound.worker.modules.nuclei;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of parsed nuclei results into findings - no
 * process/JSON work here, see {@link NucleiFetcher}/{@link
 * NucleiResultParser}.
 *
 * <p>ruleId is {@code "NUCLEI_" + templateId} rather than a hand-curated
 * rule_id - same reasoning as {@code ZapAlertMapper}'s {@code ZAP_ALERT_}
 * scheme: nuclei's template set is large (10,000+) and each already carries
 * its own stable identifier, name, description, and (usually) a reference
 * URL, so there's nothing to add by hand-writing rules_catalog copy per
 * template. Category WEB_APP, same precedent as ZAP/WHOIS/BREACH - outside
 * ScoringEngine's fixed weight table, so no rules_catalog seed rows are
 * needed here either.
 */
public final class NucleiFindingMapper {

    private NucleiFindingMapper() {}

    public static List<RawFinding> map(List<NucleiFinding> results) {
        List<RawFinding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (NucleiFinding result : results) {
            String dedupKey = result.templateId() + "|" + result.matchedAt();
            if (!seen.add(dedupKey)) {
                continue;
            }

            Map<String, Object> evidence = new LinkedHashMap<>();
            putIfPresent(evidence, "reference", result.reference());
            putIfPresent(evidence, "cveId", result.cveId());
            putIfPresent(evidence, "curlCommand", result.curlCommand());
            if (!result.extractedResults().isEmpty()) {
                evidence.put("extractedResults", result.extractedResults());
            }

            String affectedAsset = result.matchedAt() != null
                    ? result.matchedAt()
                    : (result.host() != null ? result.host() : "");

            findings.add(new RawFinding(
                    "NUCLEI_" + result.templateId(),
                    severityFor(result.severity()),
                    Category.WEB_APP,
                    result.name() == null ? "Nuclei finding (template " + result.templateId() + ")" : result.name(),
                    result.description() == null ? "" : result.description(),
                    affectedAsset,
                    evidence));
        }
        return findings;
    }

    static Severity severityFor(String nucleiSeverity) {
        if (nucleiSeverity == null) {
            return Severity.INFO;
        }
        return switch (nucleiSeverity.trim().toLowerCase(Locale.ROOT)) {
            case "critical" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> Severity.INFO; // "info", "unknown", anything else
        };
    }

    private static void putIfPresent(Map<String, Object> map, String key, String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }
}
