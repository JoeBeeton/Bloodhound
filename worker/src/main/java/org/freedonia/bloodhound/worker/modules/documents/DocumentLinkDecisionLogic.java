package org.freedonia.bloodhound.worker.modules.documents;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure interpretation of an already-fetched homepage body into a bounded
 * list of same-scheme document URLs worth downloading - no network calls,
 * fully unit-testable. Deliberately only looks at the homepage a module
 * already fetched for itself (genuinely passive, equivalent to a browser
 * loading one page) rather than crawling further - multi-page crawling is a
 * different, larger feature than "does this page link to a document that
 * leaks metadata."
 */
public final class DocumentLinkDecisionLogic {

    /** Bounded so one page linking to dozens of documents doesn't turn into dozens of downloads. */
    static final int MAX_DOCUMENTS_PER_HOST = 5;

    private static final Pattern HREF_PATTERN = Pattern.compile("(?i)href\\s*=\\s*[\"']([^\"'#]+)[\"']");
    private static final List<String> DOCUMENT_EXTENSIONS =
            List.of(".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt");

    private DocumentLinkDecisionLogic() {}

    public static List<String> extractDocumentUrls(String pageUrl, String html) {
        if (html == null || html.isBlank()) {
            return List.of();
        }
        URI base;
        try {
            base = URI.create(pageUrl);
        } catch (Exception e) {
            return List.of();
        }
        String baseHost = base.getHost();

        Set<String> results = new LinkedHashSet<>();
        Matcher matcher = HREF_PATTERN.matcher(html);
        while (matcher.find() && results.size() < MAX_DOCUMENTS_PER_HOST) {
            String href = matcher.group(1);
            if (extensionOf(href) == null) {
                continue;
            }
            try {
                URI resolved = base.resolve(href);
                String scheme = resolved.getScheme();
                if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                    continue;
                }
                // A security review found this had no host restriction at all: any http(s) link
                // with a document extension, anywhere on the internet, got downloaded (up to
                // MAX_DOCUMENTS_PER_HOST) and parsed by PDFBox/POI on the shared worker. The fetch
                // itself is already SSRF-gated elsewhere, so this isn't internal SSRF - it's an
                // untrusted-document-parser attack surface plus a bounded open fetch of arbitrary
                // third-party URLs, both worth closing. isSameSite (not exact-host-equals) so a
                // target's own CDN subdomain still works - a homepage linking its own documents
                // from a different subdomain of the same site is the common, legitimate case this
                // feature exists for; a genuinely unrelated third-party domain is not.
                if (!isSameSite(resolved.getHost(), baseHost)) {
                    continue;
                }
                results.add(resolved.toString());
            } catch (Exception e) {
                // Malformed href attribute - skip it, not worth failing the whole page over.
            }
        }
        return List.copyOf(results);
    }

    /**
     * True if one host is the other, or a subdomain of the other - checked as a proper
     * dot-anchored suffix in both directions (never a bare {@code endsWith} on the unanchored
     * string), so "example.com.evil.com" is correctly rejected as a link host for base host
     * "example.com" rather than confused for a legitimate subdomain. Deliberately not a full
     * eTLD+1/public-suffix comparison - that needs a maintained public suffix list this codebase
     * doesn't otherwise depend on; this dot-anchored subdomain check covers the actual case this
     * exists for (a homepage linking its own CDN/docs subdomain) without that dependency, at the
     * cost of not treating two independent subdomains of a shared multi-part public suffix (e.g.
     * "a.example.co.uk" and "b.example.co.uk") as the same site - a narrower, not broader, result
     * than the eTLD+1 comparison would give.
     *
     * <p>A rules-parity review found the un-bounded reverse direction a real bug, not just an
     * eTLD+1 imprecision: {@code baseHost.endsWith("." + linkHost)} with no limit on how many
     * labels get peeled lets an attacker-controlled href on the target's own homepage name
     * ANY dot-suffix of the real host - including a bare public suffix. A page at
     * "www.example.com" linking {@code href="https://com/malicious.pdf"} would have this method
     * return true ("www.example.com".endsWith(".com")), downloading and parsing a document from a
     * domain the attacker (anyone who can register under that TLD) controls, not the target's own
     * site. Bounded to peeling exactly one label - the stated legitimate case (the apex and its
     * immediate subdomain treated as the same site, in either direction) still works; an
     * arbitrary-depth/public-suffix match in the risky (reverse) direction no longer does. The
     * forward direction (linkHost an arbitrary-depth subdomain of baseHost) is left unbounded on
     * purpose - it was never the bug: a deeper, more-specific name under the real target site
     * carries no equivalent risk, since it can never resolve to a shorter public suffix the
     * attacker doesn't control.
     */
    private static boolean isSameSite(String linkHost, String baseHost) {
        if (linkHost == null || baseHost == null) {
            return false;
        }
        String a = linkHost.toLowerCase(Locale.ROOT);
        String b = baseHost.toLowerCase(Locale.ROOT);
        if (a.equals(b) || a.endsWith("." + b)) {
            return true;
        }
        return isOneLabelSubdomainOf(b, a);
    }

    /** True iff {@code host} is exactly {@code "<one-label>." + ofParent}, not an arbitrary-depth descendant. */
    private static boolean isOneLabelSubdomainOf(String host, String ofParent) {
        if (!host.endsWith("." + ofParent)) {
            return false;
        }
        String leadingLabels = host.substring(0, host.length() - ofParent.length() - 1);
        return !leadingLabels.isEmpty() && leadingLabels.indexOf('.') == -1;
    }

    private static String extensionOf(String href) {
        String path = href.toLowerCase(Locale.ROOT).split("[?#]", 2)[0];
        for (String ext : DOCUMENT_EXTENSIONS) {
            if (path.endsWith(ext)) {
                return ext;
            }
        }
        return null;
    }
}
