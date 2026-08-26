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
                results.add(resolved.toString());
            } catch (Exception e) {
                // Malformed href attribute - skip it, not worth failing the whole page over.
            }
        }
        return List.copyOf(results);
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
