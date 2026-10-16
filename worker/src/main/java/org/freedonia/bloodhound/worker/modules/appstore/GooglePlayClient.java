package org.freedonia.bloodhound.worker.modules.appstore;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Google Play has no official free search API (unlike Apple's documented iTunes Search API) -
 * this parses the rendered HTML of Play Store's own public search results page instead, the same
 * technique every unofficial "google-play-scraper"-style library uses. Explicitly fragile and
 * best-effort: Google can change this page's structure (including the specific minified CSS class
 * names matched below) at any time with no notice or versioning, unlike a documented API contract.
 * Included anyway per explicit product decision, weighing real app-store brand-impersonation
 * coverage against that maintenance risk.
 *
 * <p>Verified live before building this parser (captured 2026-10, real page for "example finance"):
 * each result renders as {@code <a href="/store/apps/details?id=<package>" ...>} followed, within
 * the same result "card", by {@code <span class="DdYX5"><app title></span>} and
 * {@code <span class="wMUdtb"><developer name></span>}. Splitting the page on every such href
 * (rather than a single whole-page regex with capture groups) keeps each card's own title/developer
 * search properly scoped to that one result instead of potentially matching a later card's spans.
 * The very first ("hero") result sometimes renders in a different card layout that this parser
 * doesn't recognize and so is silently skipped - a known, accepted gap (the grid of further
 * results below it still parses correctly), not a reason to make the whole page's HTML structure
 * more fragile to chase.
 */
@Component
public class GooglePlayClient {

    private static final Logger log = LoggerFactory.getLogger(GooglePlayClient.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final String DESKTOP_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    /** How far past each result's own href to search for its title/developer spans - generous enough to span one card's icon/screenshot markup (confirmed live: real cards need a few hundred characters) without bleeding into the next card. */
    private static final int CARD_WINDOW_CHARS = 1500;

    private static final Pattern PACKAGE_ID = Pattern.compile("^([^\"&]+)");
    private static final Pattern TITLE = Pattern.compile("class=\"DdYX5\">([^<]+)<");
    private static final Pattern DEVELOPER = Pattern.compile("class=\"wMUdtb\">([^<]+)<");
    private static final Pattern RATING = Pattern.compile("Rated ([\\d.]+) stars");

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();

    public String fetchRaw(String searchTerm) throws Exception {
        String encoded = URLEncoder.encode(searchTerm, StandardCharsets.UTF_8);
        URI uri = URI.create("https://play.google.com/store/search?q=" + encoded + "&c=apps&hl=en&gl=gb");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Play Store search returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    /** Pure - no network calls. Any parse failure (page structure changed, blocked, CAPTCHA'd) yields an empty list rather than throwing - "found nothing" and "couldn't check" are both handled the same tolerant way every other best-effort source in this codebase already uses. */
    public List<AppResult> parse(String html) {
        List<AppResult> results = new ArrayList<>();
        if (html == null || html.isBlank()) {
            return results;
        }
        try {
            String marker = "href=\"/store/apps/details?id=";
            String[] chunks = html.split(Pattern.quote(marker));
            for (int i = 1; i < chunks.length; i++) {
                String chunk = chunks[i];
                Matcher pkgMatcher = PACKAGE_ID.matcher(chunk);
                if (!pkgMatcher.find()) {
                    continue;
                }
                String appId = pkgMatcher.group(1);
                String window = chunk.substring(0, Math.min(chunk.length(), CARD_WINDOW_CHARS));
                String title = firstGroupOrNull(TITLE, window);
                String developer = firstGroupOrNull(DEVELOPER, window);
                if (title == null || developer == null) {
                    continue; // the "hero" card shape, or a genuinely unrecognized layout - skip, don't guess
                }
                String ratingText = firstGroupOrNull(RATING, window);
                results.add(new AppResult(
                        "GOOGLE_PLAY",
                        appId,
                        unescapeHtml(title),
                        unescapeHtml(developer),
                        "https://play.google.com/store/apps/details?id=" + appId,
                        ratingText != null ? Double.parseDouble(ratingText) : null,
                        null));
            }
        } catch (Exception e) {
            log.warn("Google Play search page parse failed (page structure may have changed): {}", e.toString());
            return List.of();
        }
        return results;
    }

    private static String firstGroupOrNull(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    /** The handful of HTML entities Play Store's own titles/developer names actually use (ampersands in names like "Revolut — Banking & Beyond" are the common real case) - not a general-purpose HTML decoder. */
    private static String unescapeHtml(String text) {
        return text.replace("&amp;", "&").replace("&#39;", "'").replace("&quot;", "\"");
    }
}
