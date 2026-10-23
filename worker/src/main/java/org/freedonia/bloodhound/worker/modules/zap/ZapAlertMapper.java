package org.freedonia.bloodhound.worker.modules.zap;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.worker.modules.EvidenceRedaction;

/**
 * Pure interpretation of ZAP alerts into findings - no network/JSON work
 * here, see {@link ZapScanRunner}/{@link ZapAlertParser}.
 *
 * <p>ruleId is "ZAP_ALERT_" + pluginId rather than a hand-curated rule_id
 * (unlike every other Tier 1/Tier 2 module) since ZAP's plugin set is large
 * (100+ active-scan rules) and already carries its own stable identifier,
 * title, description and remediation text per alert - there's nothing to add
 * by hand-writing rules_catalog copy for each one, and no rules_catalog seed
 * rows are needed for this module: findings are fully self-describing (see
 * RawFinding's title/description fields), and category WEB_APP is outside
 * ScoringEngine's fixed weight table (same precedent as WHOIS/BREACH) so no
 * weight lookup ever touches these rule_ids either. The one cost: WEB_APP
 * findings don't show up in the /admin/rules-catalog documentation page,
 * since that page only lists what's actually seeded - acceptable since ZAP's
 * own alert reference (the "reference" field/URL) already documents each one.
 */
public final class ZapAlertMapper {

    private ZapAlertMapper() {}

    public static List<RawFinding> map(List<ZapAlert> alerts) {
        List<RawFinding> findings = new java.util.ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (ZapAlert alert : alerts) {
            if (ZapNoiseRules.IGNORED_PLUGIN_IDS.contains(alert.pluginId())) {
                continue;
            }
            String dedupKey = alert.pluginId() + "|" + alert.url();
            if (!seen.add(dedupKey)) {
                continue;
            }
            Map<String, Object> evidence = new LinkedHashMap<>();
            putIfPresent(evidence, "solution", alert.solution());
            putIfPresent(evidence, "reference", alert.reference());
            // A security review found param/evidence copied verbatim - ZAP's own "evidence" field
            // is deliberately the exact matched substring from the request/response (a token,
            // cookie value, injected payload echoed back, etc.), and "param" is often the request
            // parameter name+value pair that triggered the alert. See EvidenceRedaction's own doc
            // for why a hash + length, not a partial preview, replaces the raw value here.
            putIfPresent(evidence, "param", EvidenceRedaction.redact(alert.param()));
            putIfPresent(evidence, "evidence", EvidenceRedaction.redact(alert.evidence()));
            putIfPresent(evidence, "confidence", alert.confidence());

            findings.add(new RawFinding(
                    "ZAP_ALERT_" + alert.pluginId(),
                    severityFor(alert.risk()),
                    Category.WEB_APP,
                    alert.name() == null ? "ZAP alert (plugin " + alert.pluginId() + ")" : alert.name(),
                    alert.description() == null ? "" : alert.description(),
                    alert.url() == null ? "" : alert.url(),
                    evidence));
        }
        return findings;
    }

    static Severity severityFor(String zapRisk) {
        if (zapRisk == null) {
            return Severity.INFO;
        }
        return switch (zapRisk.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> Severity.INFO; // "Informational" and anything unrecognized
        };
    }

    private static void putIfPresent(Map<String, Object> map, String key, String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }
}
