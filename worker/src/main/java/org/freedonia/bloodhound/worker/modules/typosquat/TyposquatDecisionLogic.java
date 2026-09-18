package org.freedonia.bloodhound.worker.modules.typosquat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure decision half: a checked candidate becomes a finding purely because it
 * resolves (registered + live) - registration alone is the actionable
 * signal, per the product decision that proving active phishing content is a
 * separate, paid-tooling-dependent capability out of scope here. No database
 * access, no "is this new" comparison needed (unlike SubdomainIngestionService's
 * findings): whether a candidate is registered is knowable from this scan
 * alone, so the module emits these findings directly rather than routing
 * through a central-server ingestion detour the way SUBDOMAIN_ENUM/WHOIS do.
 *
 * <p>A candidate flagged {@code wildcardArtifact} by {@link TyposquatChecker}
 * is never emitted as a finding, even though it technically resolves: that
 * resolution came from its parent zone answering for literally any
 * subdomain, not from anyone registering this specific lookalike label - not
 * real typosquatting signal, just noise from an unrelated wildcarded zone.
 */
public final class TyposquatDecisionLogic {

    private TyposquatDecisionLogic() {}

    public static List<RawFinding> decide(List<TyposquatChecker.CheckedCandidate> checked) {
        List<RawFinding> findings = new ArrayList<>();
        for (TyposquatChecker.CheckedCandidate candidate : checked) {
            if (candidate.resolvedIps().isEmpty() || candidate.wildcardArtifact()) {
                continue;
            }
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("permutationType", candidate.permutationType());
            evidence.put("resolvedIps", candidate.resolvedIps());
            if (candidate.registrationDate() != null) {
                evidence.put("registrationDate", candidate.registrationDate().toString());
            }
            if (candidate.visualSimilarityPercent() != null) {
                evidence.put("visualSimilarityPercent", candidate.visualSimilarityPercent());
            }
            String humanType =
                    candidate.permutationType().toLowerCase(Locale.ROOT).replace('_', ' ');
            String description = "A domain closely resembling this target's own (a " + humanType
                    + " variant) is registered and actively resolving, which is consistent with "
                    + "typosquatting or brand-impersonation infrastructure - though it can occasionally be "
                    + "a coincidentally similarly-named, unrelated legitimate site.";
            if (candidate.visualSimilarityPercent() != null) {
                description += " Its homepage's visual layout is " + candidate.visualSimilarityPercent()
                        + "% similar to the real target's, based on a screenshot comparison - "
                        + (candidate.visualSimilarityPercent() >= 80
                                ? "a strong additional signal that this may be an actual clone/impersonation, not just a coincidental name."
                                : "a comparatively weak visual match, which leans toward coincidental naming rather than a rendered clone.");
            }
            findings.add(new RawFinding(
                    "TYPOSQUAT_DOMAIN_REGISTERED",
                    Severity.HIGH,
                    Category.BRAND,
                    "Registered lookalike domain: " + candidate.domain(),
                    description,
                    candidate.domain(),
                    evidence));

            // Escalations of the base finding above, not alternatives to it - a parked
            // registration and one actively staged to receive phishing-reply mail or serve a
            // cloned login page are very different risk tiers, even though both trip
            // TYPOSQUAT_DOMAIN_REGISTERED first.
            if (candidate.mxConfigured()) {
                findings.add(new RawFinding(
                        "BRAND_TYPOSQUAT_MX_CONFIGURED",
                        Severity.CRITICAL,
                        Category.BRAND,
                        "Lookalike domain has mail servers configured: " + candidate.domain(),
                        "This registered lookalike domain (a " + humanType + " variant of this target's own) has "
                                + "MX records configured - it isn't just parked, it's set up to receive email. That's "
                                + "consistent with actively staging the domain for phishing-reply capture or "
                                + "business-email-compromise, not a coincidental or defensive registration.",
                        candidate.domain(),
                        Map.of("permutationType", candidate.permutationType())));
            }
            // screenshotPng is only ever attempted for a genuine candidate once the real target's
            // OWN screenshot has already succeeded (see check() above) - so, same caveat the
            // existing visualSimilarityPercent signal already carries, a transient screenshotter
            // failure on the real site suppresses this finding for every candidate in the batch,
            // not just a missed comparison score. Best-effort, not a guarantee.
            if (candidate.screenshotPng() != null) {
                findings.add(new RawFinding(
                        "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE",
                        Severity.CRITICAL,
                        Category.BRAND,
                        "Lookalike domain is hosting a live website: " + candidate.domain(),
                        "This registered lookalike domain (a " + humanType + " variant of this target's own) is "
                                + "serving a live, renderable web page - not just holding a DNS record. Combined "
                                + "with " + (candidate.visualSimilarityPercent() != null
                                        ? "a " + candidate.visualSimilarityPercent() + "% visual-similarity match to the real site, "
                                        : "the registration itself, ")
                                + "this is consistent with active phishing/impersonation content, not a parked or "
                                + "defensively-registered domain.",
                        candidate.domain(),
                        Map.of("permutationType", candidate.permutationType())));
            }
        }
        return findings;
    }
}
