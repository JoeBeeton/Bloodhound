package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.List;
import java.util.Optional;

/**
 * Pure decision logic for dangling-CNAME / subdomain-takeover detection.
 * Deliberately a small, high-confidence subset of the well-known
 * "can-i-take-over-xyz"-style reference list (which runs to 60+ entries),
 * expanded once already (8 -&gt; 14, see EdOverflow/can-i-take-over-xyz and
 * vulnsy.com's cheat sheet cross-referenced while adding these) - covers the
 * most common real-world takeover vectors with a high-confidence, sufficiently
 * distinctive fingerprint for each, deliberately excluding that reference
 * list's own "Edge case"/"Not vulnerable" entries (Tumblr, WordPress.com,
 * Netlify, Vercel, Intercom, Webflow, Ghost, CloudFront, Unbounce, StatusPage)
 * where the same-looking response can occur without the subdomain actually
 * being claimable, or where the provider now requires additional
 * domain-ownership verification the fingerprint alone can't detect.
 *
 * Matching a CNAME against {@link #matchProvider} only identifies which
 * service *type* a subdomain points at - it says nothing about whether the
 * resource is actually unclaimed. A positive finding requires BOTH a CNAME
 * match AND {@link #isUnclaimed} confirming the specific "nothing here"
 * fingerprint in a live HTTP response body, exactly the same
 * pattern-plus-signature discipline ExposedPathDecisionLogic uses to avoid
 * false positives.
 *
 * Fingerprints use substring "contains" matching rather than a strict
 * hostname suffix match: AWS S3's website-hosting CNAME target embeds a
 * region name between the fixed parts (e.g.
 * "bucket.s3-website-us-east-1.amazonaws.com"), so a plain suffix check on
 * ".s3-website" would never match any real S3-website CNAME. "Contains" on
 * these specific, sufficiently-distinctive substrings handles that case
 * correctly while remaining just as precise for the other six services.
 */
final class DanglingCnameDecisionLogic {

    record TakeoverService(String cnameFragment, String serviceName, String unclaimedFingerprint) {}

    static final List<TakeoverService> KNOWN_SERVICES = List.of(
            new TakeoverService(".s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
            new TakeoverService(".s3-website", "AWS S3", "NoSuchBucket"),
            new TakeoverService(".github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
            new TakeoverService(".herokuapp.com", "Heroku", "No such app"),
            new TakeoverService(".azurewebsites.net", "Azure Web App", "404 Web Site not found"),
            new TakeoverService(".zendesk.com", "Zendesk", "Help Center Closed"),
            new TakeoverService(".myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
            new TakeoverService(".fastly.net", "Fastly", "Fastly error: unknown domain"),
            new TakeoverService(".bitbucket.io", "Bitbucket", "Repository not found"),
            new TakeoverService(
                    ".pantheonsite.io", "Pantheon", "The gods are wise, but do not know of the site which you seek"),
            new TakeoverService(".surge.sh", "Surge.sh", "project not found"),
            new TakeoverService(".readme.io", "Readme.io", "Project doesnt exist... yet!"),
            new TakeoverService(".helpscoutdocs.com", "Help Scout", "No settings were found for this company"),
            new TakeoverService(".cargocollective.com", "Cargo Collective", "moving your domain away from Cargo"));

    private DanglingCnameDecisionLogic() {}

    static Optional<TakeoverService> matchProvider(String cnameTarget) {
        if (cnameTarget == null || cnameTarget.isBlank()) {
            return Optional.empty();
        }
        String lower = cnameTarget.toLowerCase();
        return KNOWN_SERVICES.stream().filter(s -> lower.contains(s.cnameFragment())).findFirst();
    }

    static boolean isUnclaimed(TakeoverService service, String responseBody) {
        return responseBody != null && responseBody.contains(service.unclaimedFingerprint());
    }
}
