package org.freedonia.bloodhound.worker.modules.appstore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * App-store brand-impersonation monitoring: searches Apple's App Store (official iTunes Search
 * API) and Google Play (page-scraped, see {@link GooglePlayClient}'s own javadoc on that
 * tradeoff) for the target's brand name, flagging listings that mention the brand but aren't
 * published under a developer name that itself contains it - see {@link AppStoreDecisionLogic}.
 * Closes a real gap in this product's brand-protection coverage: {@code typosquat}'s domain-level
 * checks have no equivalent for the app-store channel at all.
 *
 * <p>Root hostname only, same scope as {@code TYPOSQUAT_MONITOR} (a lookalike app is a property of
 * the brand, not of any one subdomain) - never fanned out across subdomains.
 *
 * <p>Brand term is the hostname's first label only (e.g. "example" from "example.co.uk", "monzo" from
 * "monzo.com") - deliberately simpler than PermutationGenerator/BucketNameGenerator's own
 * multi-label stem (which exists specifically for bucket/permutation naming conventions): an app
 * store listing's title uses the brand's actual word, not a hyphen-joined domain-label stem.
 */
@Component
public class AppStoreMonitorModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(AppStoreMonitorModule.class);
    private static final int MIN_BRAND_TERM_LENGTH = 3;

    /** Both stores rank results by title/keyword relevance to the search term - a genuine
     * brand-impersonating app ranks high for an exact-brand-name search, while a coincidental
     * same-word app (see class javadoc: "example" is also an informal word in several languages)
     * tends to rank lower once mixed with install/rating signals. Capping to each store's own
     * top results leans on that ranking to do real denoising, rather than inventing an
     * unavailable industry/qualifier term to append to the search. */
    private static final int MAX_RESULTS_PER_STORE = 10;

    private final AppleAppStoreClient appleClient;
    private final GooglePlayClient googlePlayClient;

    public AppStoreMonitorModule(AppleAppStoreClient appleClient, GooglePlayClient googlePlayClient) {
        this.appleClient = appleClient;
        this.googlePlayClient = googlePlayClient;
    }

    @Override
    public String moduleType() {
        return "APP_STORE_MONITOR";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String brandTerm = brandTerm(context.hostname());
        if (brandTerm == null) {
            return new ModuleResult(List.of(), Map.of("skipped", "brand term too short to search safely"));
        }

        List<AppResult> results = new ArrayList<>();
        results.addAll(capped(fetchApple(brandTerm)));
        results.addAll(capped(fetchGooglePlay(brandTerm)));

        List<RawFinding> findings = AppStoreDecisionLogic.decide(context.hostname(), brandTerm, results);

        List<Map<String, Object>> resultMetadata = new ArrayList<>();
        for (AppResult r : results) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("store", r.store());
            entry.put("appId", r.appId());
            entry.put("title", r.title());
            entry.put("developer", r.developer());
            entry.put("url", r.url());
            resultMetadata.add(entry);
        }
        Map<String, Object> rawMetadata = new LinkedHashMap<>();
        rawMetadata.put("brandTerm", brandTerm);
        rawMetadata.put("resultsChecked", results.size());
        rawMetadata.put("results", resultMetadata);
        return new ModuleResult(findings, rawMetadata);
    }

    private List<AppResult> fetchApple(String searchTerm) {
        try {
            return appleClient.parse(appleClient.fetchRaw(searchTerm));
        } catch (Exception e) {
            log.warn("Apple App Store search failed, skipping this run: {}", e.toString());
            return List.of();
        }
    }

    private List<AppResult> fetchGooglePlay(String searchTerm) {
        try {
            return googlePlayClient.parse(googlePlayClient.fetchRaw(searchTerm));
        } catch (Exception e) {
            log.warn("Google Play search failed, skipping this run: {}", e.toString());
            return List.of();
        }
    }

    private static List<AppResult> capped(List<AppResult> results) {
        return results.size() > MAX_RESULTS_PER_STORE ? results.subList(0, MAX_RESULTS_PER_STORE) : results;
    }

    /** Null (skip entirely) for a too-short first label - same floor PermutationGenerator/BucketNameGenerator already use for their own stems, to avoid an absurdly broad single/double-character search. */
    static String brandTerm(String hostname) {
        String first = hostname.toLowerCase(Locale.ROOT).split("\\.")[0];
        return first.length() >= MIN_BRAND_TERM_LENGTH ? first : null;
    }
}
