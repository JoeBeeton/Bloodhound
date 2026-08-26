package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure interpretation of an already-fetched homepage body into the distinct
 * external origins a page's {@code <script>}/{@code <iframe>} tags actually
 * load from - no network calls, fully unit-testable. Info-level signal only
 * (see {@link FingerprintModule}, which surfaces this the same way as
 * technologies/hostingProvider: informational rawMetadata, not a scored
 * finding) - "how many third parties does this page actually trust" is
 * useful supply-chain visibility (analytics, tag managers, chat/embed
 * widgets) regardless of whether any individual origin is itself a problem.
 */
public final class ThirdPartyOriginDecisionLogic {

    private static final Pattern SRC_PATTERN =
            Pattern.compile("(?i)<(?:script|iframe)\\b[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']");

    private ThirdPartyOriginDecisionLogic() {}

    /**
     * @param pageUrl the fetched page's own URL - resolves relative {@code src} attributes and anchors the "own host" comparison
     * @param html the already-fetched homepage body
     * @param targetRootHostname the target's own root hostname - an origin whose host equals this or ends with {@code "." + this} is "ours," not third-party
     * @param knownSubdomains the target's other known hostnames, same "ours" treatment
     */
    public static List<String> extractThirdPartyOrigins(
            String pageUrl, String html, String targetRootHostname, Collection<String> knownSubdomains) {
        if (html == null || html.isBlank()) {
            return List.of();
        }
        URI base;
        try {
            base = URI.create(pageUrl);
        } catch (Exception e) {
            return List.of();
        }

        Set<String> ownHostnames = new HashSet<>();
        if (targetRootHostname != null) {
            ownHostnames.add(targetRootHostname.toLowerCase(Locale.ROOT));
        }
        if (knownSubdomains != null) {
            for (String sub : knownSubdomains) {
                if (sub != null) {
                    ownHostnames.add(sub.toLowerCase(Locale.ROOT));
                }
            }
        }

        Set<String> origins = new LinkedHashSet<>();
        Matcher matcher = SRC_PATTERN.matcher(html);
        while (matcher.find()) {
            try {
                URI resolved = base.resolve(matcher.group(1));
                String scheme = resolved.getScheme();
                String host = resolved.getHost();
                if (scheme == null || host == null) {
                    continue;
                }
                if (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) {
                    continue;
                }
                String lowerHost = host.toLowerCase(Locale.ROOT);
                if (isOwnHost(lowerHost, targetRootHostname, ownHostnames)) {
                    continue;
                }
                origins.add(scheme.toLowerCase(Locale.ROOT) + "://" + lowerHost);
            } catch (Exception e) {
                // Malformed src attribute - skip it, not worth failing the whole page over.
            }
        }
        return origins.stream().sorted().toList();
    }

    private static boolean isOwnHost(String host, String targetRootHostname, Set<String> ownHostnames) {
        if (ownHostnames.contains(host)) {
            return true;
        }
        return targetRootHostname != null && host.endsWith("." + targetRootHostname.toLowerCase(Locale.ROOT));
    }
}
