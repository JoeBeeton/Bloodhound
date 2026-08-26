package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure interpretation of an already-fetched response into a technology list -
 * no network calls, fully unit-testable. A deliberately bounded, curated
 * signature catalog (~28 entries) covering the most common real-world CMSs,
 * frameworks, JS libraries, CDNs and analytics tools - not an attempt to
 * replicate Wappalyzer's multi-thousand-entry database. Matches are
 * deduplicated by technology name (a page can trigger the same signature via
 * more than one path, e.g. both a cookie and a generator tag for WordPress).
 */
public final class TechDecisionLogic {

    private TechDecisionLogic() {}

    public static List<Technology> decide(TechFetchResult result) {
        Map<String, Technology> found = new LinkedHashMap<>();
        Map<String, String> headers = result.headers();
        String server = headers.getOrDefault("server", "").toLowerCase();
        String poweredBy = headers.getOrDefault("x-powered-by", "").toLowerCase();
        String bodyLower = result.body() == null ? "" : result.body().toLowerCase();
        String cookiesLower = String.join("\n", result.setCookieHeaders()).toLowerCase();

        // Web servers / CDN edge, from the Server header. Version-capturing
        // where the header realistically carries one ("nginx/1.31.4",
        // "Apache/2.4.58 (Ubuntu)") - the raw (not lowercased) Server header
        // is used for the regex so the extracted version string itself isn't
        // mangled, matching is still done against the lowercased copy.
        String serverRaw = headers.getOrDefault("server", "");
        addWithVersion(found, server.contains("nginx"), "nginx", Technology.WEB_SERVER,
                extractVersion(serverRaw, "nginx/([\\d.]+)"));
        addWithVersion(found, server.contains("apache"), "Apache", Technology.WEB_SERVER,
                extractVersion(serverRaw, "Apache/([\\d.]+)"));
        addIf(found, server.contains("iis"), "IIS", Technology.WEB_SERVER);
        addIf(found, server.contains("cloudflare"), "Cloudflare", Technology.CDN);
        addIf(found, headers.containsKey("cf-ray") || bodyLower.contains("cdn-cgi/"), "Cloudflare", Technology.CDN);

        // Language runtime / framework, from X-Powered-By and cookie names.
        String poweredByRaw = headers.getOrDefault("x-powered-by", "");
        addWithVersion(found, poweredBy.contains("php"), "PHP", Technology.LANGUAGE_RUNTIME,
                extractVersion(poweredByRaw, "PHP/([\\d.]+)"));
        addIf(found, poweredBy.contains("express"), "Express", Technology.FRAMEWORK);
        addIf(found, poweredBy.contains("asp.net") || headers.containsKey("x-aspnet-version"), "ASP.NET", Technology.FRAMEWORK);
        addIf(found, cookiesLower.contains("phpsessid"), "PHP", Technology.LANGUAGE_RUNTIME);
        addIf(found, cookiesLower.contains("jsessionid"), "Java/JSP", Technology.LANGUAGE_RUNTIME);
        addIf(found, cookiesLower.contains("asp.net_sessionid") || cookiesLower.contains(".aspxauth"), "ASP.NET", Technology.FRAMEWORK);

        // CMS platforms. WordPress's version, when present, comes from its
        // own generator meta tag ("<meta name=\"generator\" content=\"WordPress 6.4.2\">"),
        // not from any header - extracted from the original-case body since
        // the version digits themselves are case-insensitive but nearby
        // attribute text isn't guaranteed to survive lowercasing cleanly.
        addWithVersion(found,
                cookiesLower.contains("wordpress_logged_in") || cookiesLower.contains("wp-settings")
                        || bodyLower.contains("wp-content/") || bodyLower.contains("generator\" content=\"wordpress"),
                "WordPress", Technology.CMS,
                extractVersion(result.body() == null ? "" : result.body(), "WordPress ([\\d.]+)"));
        addIf(found, bodyLower.contains("drupal.settings") || bodyLower.contains("generator\" content=\"drupal"),
                "Drupal", Technology.CMS);
        addIf(found, bodyLower.contains("generator\" content=\"joomla"), "Joomla", Technology.CMS);
        addIf(found, bodyLower.contains("cdn.shopify.com") || bodyLower.contains("shopify.theme"), "Shopify", Technology.CMS);
        addIf(found, bodyLower.contains("static.squarespace.com") || bodyLower.contains("squarespace_context"),
                "Squarespace", Technology.CMS);
        addIf(found, bodyLower.contains("wixstatic.com") || bodyLower.contains("wix.com/services"), "Wix", Technology.CMS);

        // JS frameworks/libraries.
        addIf(found, bodyLower.contains("jquery"), "jQuery", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("data-reactroot") || bodyLower.contains("react-dom"), "React", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("__next_data__"), "Next.js", Technology.FRAMEWORK);
        addIf(found, bodyLower.contains("data-v-") || bodyLower.contains("__vue__") || bodyLower.contains("vue.js"),
                "Vue.js", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("ng-version"), "Angular", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("bootstrap.min.css") || bodyLower.contains("bootstrap.min.js") || bodyLower.contains("bootstrap.bundle"),
                "Bootstrap", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("font-awesome") || bodyLower.contains("fontawesome"), "Font Awesome", Technology.JS_LIBRARY);

        // Analytics / third-party embeds.
        addIf(found, bodyLower.contains("google-analytics.com") || bodyLower.contains("googletagmanager.com/gtag")
                        || bodyLower.contains("googleanalyticsobject"),
                "Google Analytics", Technology.ANALYTICS);
        addIf(found, bodyLower.contains("googletagmanager.com/gtm.js"), "Google Tag Manager", Technology.ANALYTICS);
        addIf(found, bodyLower.contains("fonts.googleapis.com"), "Google Fonts", Technology.CDN);
        addIf(found, bodyLower.contains("recaptcha") && bodyLower.contains("gstatic.com"), "reCAPTCHA", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("js.stripe.com"), "Stripe", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("cdn.segment.com"), "Segment", Technology.ANALYTICS);

        return List.copyOf(found.values());
    }

    private static void addIf(Map<String, Technology> found, boolean matched, String name, String category) {
        if (matched) {
            found.putIfAbsent(name, new Technology(name, category, null));
        }
    }

    private static void addWithVersion(
            Map<String, Technology> found, boolean matched, String name, String category, String version) {
        if (matched) {
            found.putIfAbsent(name, new Technology(name, category, version));
        }
    }

    /** Null if the pattern doesn't match - matching failing (or the underlying field being absent) is the common case, not an error. */
    private static String extractVersion(String source, String pattern) {
        if (source == null || source.isBlank()) {
            return null;
        }
        Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(source);
        return m.find() ? m.group(1) : null;
    }
}
