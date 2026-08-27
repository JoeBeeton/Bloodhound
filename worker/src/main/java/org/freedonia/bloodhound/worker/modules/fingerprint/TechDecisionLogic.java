package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure interpretation of an already-fetched response into a technology list -
 * no network calls, fully unit-testable. A deliberately bounded, curated
 * signature catalog covering the most common real-world CMSs, frameworks,
 * JS libraries, CDNs and analytics tools - not an attempt to replicate
 * Wappalyzer's multi-thousand-entry database (whose fingerprint data is
 * GPLv3-licensed in any case - see both of its current upstream sources,
 * enthec/webappanalyzer and HTTPArchive/wappalyzer - so reusing it here
 * would conflict with this project's Apache-2.0 license the same way nmap's
 * did; every signature below is independently written against publicly
 * observable, objective facts about how each technology's own output is
 * structured, not derived from anyone's proprietary/copyleft database).
 * Matches are
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
        addWithVersion(found, server.contains("iis"), "IIS", Technology.WEB_SERVER,
                extractVersion(serverRaw, "IIS/([\\d.]+)"));
        addIf(found, server.contains("cloudflare"), "Cloudflare", Technology.CDN);
        addIf(found, headers.containsKey("cf-ray") || bodyLower.contains("cdn-cgi/"), "Cloudflare", Technology.CDN);
        addGenericWebServer(found, server, serverRaw);

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
        // x-redirect-by is set by WordPress's own canonical-URL redirect (e.g. a bare domain
        // redirecting to www., or vice versa) - confirmed live against a real target where it
        // was the *only* WordPress signal available at all: the destination page itself had no
        // generator tag, no wp-content reference, nothing, evidently a heavily de-branded/headless
        // setup. Requires TechFetcher's redirect-chain-aware fetch (see its own javadoc) - a plain
        // final-response-only fetch never sees this header, since it lives on the redirect hop.
        addWithVersion(found,
                cookiesLower.contains("wordpress_logged_in") || cookiesLower.contains("wp-settings")
                        || bodyLower.contains("wp-content/") || bodyLower.contains("generator\" content=\"wordpress")
                        || "wordpress".equals(headers.getOrDefault("x-redirect-by", "").toLowerCase()),
                "WordPress", Technology.CMS,
                extractVersion(result.body() == null ? "" : result.body(), "WordPress ([\\d.]+)"));
        // Drupal's generator tag carries only the major version ("Drupal 10 (https://www.drupal.org)"),
        // never a precise minor/patch - coarser than the other version captures here, but still
        // genuinely useful for CVE correlation, which is commonly major-version-scoped anyway.
        addWithVersion(found, bodyLower.contains("drupal.settings") || bodyLower.contains("generator\" content=\"drupal"),
                "Drupal", Technology.CMS, extractVersion(result.body() == null ? "" : result.body(), "Drupal (\\d+)"));
        // Joomla strips the version number from its generator tag by default since Joomla 3.x -
        // name-only detection is genuinely the ceiling for this signal on a normally-configured site.
        addIf(found, bodyLower.contains("generator\" content=\"joomla"), "Joomla", Technology.CMS);
        addIf(found, bodyLower.contains("cdn.shopify.com") || bodyLower.contains("shopify.theme"), "Shopify", Technology.CMS);
        addIf(found, bodyLower.contains("static.squarespace.com") || bodyLower.contains("squarespace_context"),
                "Squarespace", Technology.CMS);
        addIf(found, bodyLower.contains("wixstatic.com") || bodyLower.contains("wix.com/services"), "Wix", Technology.CMS);
        // No generator tag or any other passive version signal exists for Magento - name-only,
        // same ceiling as Joomla above.
        addIf(found, headers.containsKey("x-magento-cache-debug") || bodyLower.contains("mage-cache-storage")
                        || bodyLower.contains("mage.cookies"),
                "Magento", Technology.CMS);
        addWordPressPluginsAndThemes(found, result.body());

        // JS frameworks/libraries. Version, where captured, comes from the CDN path or filename
        // (both jsDelivr/cdnjs-style "libname/X.Y.Z/..." or "libname@X.Y.Z" and the version query
        // string WordPress's own enqueue system appends to self-hosted copies, "libname.min.js?ver=X.Y.Z")
        // - a bundled/minified file with neither carries no reliable passive version signal at all.
        String bodyRaw = result.body() == null ? "" : result.body();
        addWithVersion(found, bodyLower.contains("jquery"), "jQuery", Technology.JS_LIBRARY,
                firstNonNull(
                        extractVersion(bodyRaw, "(?:^|/)jquery[-/]([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)"),
                        extractVersion(bodyRaw, "(?:^|/)jquery(?:\\.min)?\\.js\\?\\S*?ver=([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)")));
        addIf(found, bodyLower.contains("data-reactroot") || bodyLower.contains("react-dom"), "React", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("__next_data__"), "Next.js", Technology.FRAMEWORK);
        addIf(found, bodyLower.contains("data-v-") || bodyLower.contains("__vue__") || bodyLower.contains("vue.js"),
                "Vue.js", Technology.JS_LIBRARY);
        addIf(found, bodyLower.contains("ng-version"), "Angular", Technology.JS_LIBRARY);
        // Anchored to "/bootstrap" as the actual filename stem, not a bare substring, for both
        // presence and version - confirmed for real against example.co.uk: Trustpilot's widget
        // script is literally named "tp.widget.bootstrap.min.js?ver=1.0" (Trustpilot's own
        // widget-init naming, nothing to do with Twitter Bootstrap). The original unanchored
        // bodyLower.contains("bootstrap.min.js") matched that filename as a plain substring -
        // wrong not just about the version, but about Bootstrap being present at all.
        addWithVersion(found,
                matchesAnchored(bodyLower, "(?:^|/)bootstrap(?:\\.bundle)?(?:\\.min)?\\.(?:css|js)"),
                "Bootstrap", Technology.JS_LIBRARY,
                firstNonNull(
                        extractVersion(bodyRaw, "(?:^|/)bootstrap(?:@|/)([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)"),
                        extractVersion(bodyRaw, "(?:^|/)bootstrap(?:\\.bundle)?(?:\\.min)?\\.(?:css|js)\\?\\S*?ver=([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)")));
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

    private static final Pattern GENERIC_SERVER_PRODUCT_VERSION = Pattern.compile("^([A-Za-z][\\w.+-]*)/([\\d][\\w.-]*)");

    /**
     * Any Server header value not already matched by one of the named signatures above still gets
     * surfaced rather than silently dropped - confirmed live against real tracked targets that this
     * was a genuine coverage gap, not a hypothetical one: GitHub.com's edge discloses a bare
     * {@code Server: GitHub.com} and gets dropped entirely today, the same as any other bespoke or
     * less-common server product (LiteSpeed, openresty, Caddy, Kestrel, gunicorn, ...) none of which
     * has (or needs) its own dedicated signature. Version is still captured wherever the header
     * follows the standard "Product/X.Y.Z" convention (e.g. "openresty/1.21.4.1"); a bare product
     * name with no slash (like GitHub's) is still worth reporting name-only, same as Joomla/Magento
     * above. Deliberately excludes anything already claimed by a more specific signature (nginx,
     * Apache, IIS) or by the Cloudflare CDN check just above - re-adding those under a second,
     * cruder name would be redundant, not additive.
     */
    private static void addGenericWebServer(Map<String, Technology> found, String serverLower, String serverRaw) {
        if (serverRaw.isBlank()
                || serverLower.contains("cloudflare")
                || serverLower.contains("nginx")
                || serverLower.contains("apache")
                || serverLower.contains("iis")) {
            return;
        }
        String token = serverRaw.split("[\\s(]")[0];
        if (token.isBlank()) {
            return;
        }
        Matcher m = GENERIC_SERVER_PRODUCT_VERSION.matcher(token);
        if (m.find()) {
            found.putIfAbsent(m.group(1), new Technology(m.group(1), Technology.WEB_SERVER, m.group(2)));
        } else {
            found.putIfAbsent(token, new Technology(token, Technology.WEB_SERVER, null));
        }
    }

    /**
     * WordPress enqueues every plugin/theme asset with a {@code ?ver=X.Y.Z}
     * query string by default (its own cache-busting convention, not
     * something Bloodhound has to guess at) - so a plugin/theme slug plus
     * version is sitting in plain sight in the page source for any
     * WordPress site that hasn't deliberately stripped it. Each is reported
     * as its own {@link Technology} entry (informational - see
     * FingerprintModule's own javadoc for why this module never emits
     * findings directly), distinct from CVE-correlated WordPress core:
     * mapping individual plugin slugs to NVD CPE products isn't attempted
     * here - ProductSlugMapper stays a small, curated, verified list, and
     * there are tens of thousands of plugin slugs, not a handful.
     */
    private static final Pattern WP_PLUGIN_ASSET =
            Pattern.compile("wp-content/plugins/([a-zA-Z0-9_-]+)/[^\"'\\s]*\\?\\S*?ver=([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)");
    private static final Pattern WP_THEME_ASSET =
            Pattern.compile("wp-content/themes/([a-zA-Z0-9_-]+)/[^\"'\\s]*\\?\\S*?ver=([\\d]+\\.[\\d]+(?:\\.[\\d]+)?)");

    private static void addWordPressPluginsAndThemes(Map<String, Technology> found, String body) {
        if (body == null || body.isBlank()) {
            return;
        }
        addAllMatches(found, WP_PLUGIN_ASSET, body, "WordPress Plugin: ");
        addAllMatches(found, WP_THEME_ASSET, body, "WordPress Theme: ");
    }

    private static void addAllMatches(Map<String, Technology> found, Pattern pattern, String body, String namePrefix) {
        Matcher matcher = pattern.matcher(body);
        while (matcher.find()) {
            String name = namePrefix + matcher.group(1);
            found.putIfAbsent(name, new Technology(name, Technology.CMS, matcher.group(2)));
        }
    }

    private static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    /** Like {@link String#contains} but the match must sit at a path-segment boundary (start of the string or right after a "/"), not anywhere inside a longer unrelated filename. */
    private static boolean matchesAnchored(String body, String pattern) {
        return body != null && Pattern.compile(pattern).matcher(body).find();
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
