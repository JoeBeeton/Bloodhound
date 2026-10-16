package org.freedonia.bloodhound.worker.modules.appstore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure decision logic: an app result is suspicious when its own title mentions this target's
 * brand but its publisher/developer name doesn't - no stored "known legitimate publisher" list is
 * needed at all, since a brand's own real apps are reliably published under a developer name that
 * itself contains the brand (confirmed live: Jaja Finance Ltd's real App Store listings all show
 * seller name "Jaja Finance Ltd" or "JaJa Credit"; a genuinely unrelated one found live in the same
 * search, "JAJA Finance Tracker", was published by an unrelated individual developer name with no
 * trace of "jaja" in it at all). A real, if imperfect, heuristic - like every other brand-adjacent
 * check in this codebase (typosquat domains, TLS_CT_UNEXPECTED_ISSUER), this is "worth a human
 * look", not proof: an unofficial fan tracker or review aggregator can legitimately mention a brand
 * by name without being malicious.
 */
public final class AppStoreDecisionLogic {

    private AppStoreDecisionLogic() {}

    public static List<RawFinding> decide(String hostname, String brandTerm, List<AppResult> results) {
        List<RawFinding> findings = new ArrayList<>();
        String term = brandTerm.toLowerCase(Locale.ROOT);
        for (AppResult result : results) {
            if (result.title() == null || !result.title().toLowerCase(Locale.ROOT).contains(term)) {
                continue;
            }
            boolean developerMatchesBrand =
                    result.developer() != null && result.developer().toLowerCase(Locale.ROOT).contains(term);
            if (developerMatchesBrand) {
                continue;
            }
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("store", result.store());
            evidence.put("appId", result.appId());
            evidence.put("title", result.title());
            evidence.put("developer", result.developer() == null ? "" : result.developer());
            if (result.url() != null) {
                evidence.put("url", result.url());
            }
            if (result.rating() != null) {
                evidence.put("rating", result.rating());
            }
            if (result.ratingCount() != null) {
                evidence.put("ratingCount", result.ratingCount());
            }
            String storeLabel = "GOOGLE_PLAY".equals(result.store()) ? "Google Play" : "the Apple App Store";
            findings.add(new RawFinding(
                    "BRAND_IMPERSONATING_APP_DETECTED",
                    Severity.MEDIUM,
                    Category.BRAND,
                    "App on " + storeLabel + " uses this brand's name: " + result.title(),
                    "An app titled \"" + result.title() + "\" on " + storeLabel + " mentions this organization's "
                            + "brand name, but is published by \"" + (result.developer() == null || result.developer().isBlank()
                                    ? "an unknown developer"
                                    : result.developer())
                            + "\" - a name that doesn't itself contain the brand, unlike this organization's own "
                            + "real app listings. This can be a legitimate unofficial fan app or review tool, but "
                            + "is also a pattern seen with fake banking/finance apps designed to phish credentials "
                            + "or card details - worth a human review of the listing itself.",
                    result.url() != null ? result.url() : result.store() + ": " + result.appId(),
                    evidence));
        }
        return findings;
    }
}
