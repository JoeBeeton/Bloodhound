package org.freedonia.bloodhound.worker.modules.http;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of an already-fetched response into findings - no network calls, fully unit-testable. */
public final class HttpHeaderParser {

    private HttpHeaderParser() {}

    // Flags a banner disclosing a version number (e.g. "Apache/2.4.41",
    // "PHP/7.4.3"); a bare product name with no version is left alone.
    private static final Pattern VERSION_LIKE = Pattern.compile("\\d+\\.\\d+");

    public static List<RawFinding> parse(String hostname, FetchResult result) {
        List<RawFinding> findings = new ArrayList<>();
        Map<String, String> headers = result.headers();

        requireHeader(findings, headers, hostname, "content-security-policy", "HEADER_CSP_MISSING", Severity.MEDIUM);
        requireHeader(findings, headers, hostname, "x-frame-options", "HEADER_XFO_MISSING", Severity.LOW);
        requireHeader(findings, headers, hostname, "x-content-type-options", "HEADER_XCTO_MISSING", Severity.LOW);
        requireHeader(findings, headers, hostname, "referrer-policy", "HEADER_REFERRER_POLICY_MISSING", Severity.INFO);
        requireHeader(
                findings, headers, hostname, "permissions-policy", "HEADER_PERMISSIONS_POLICY_MISSING", Severity.INFO);

        findings.addAll(httpsRedirectFindings(hostname, result));

        String banner = (headers.getOrDefault("server", "") + " " + headers.getOrDefault("x-powered-by", "")).trim();
        if (!banner.isEmpty() && VERSION_LIKE.matcher(banner).find()) {
            findings.add(finding("HEADER_SERVER_BANNER_VERBOSE", Severity.INFO, hostname, Map.of("banner", banner)));
        }

        // Every Set-Cookie is checked, not just ones that look session-like -
        // name-sniffing ("sess"/"token"/"auth") is fragile and incomplete;
        // any cookie missing these flags is a real hardening gap regardless
        // of its apparent purpose. Asset is "hostname: cookie-name" rather
        // than just the cookie name - now that this module scans a target's
        // subdomains too, several hosts can legitimately set same-named
        // cookies (e.g. "session"), and the hostname must stay visible in
        // the asset to keep those findings distinct rather than colliding
        // under central-server's (target_id, rule_id, affected_asset) dedup
        // key.
        for (String setCookie : result.setCookieHeaders()) {
            String asset = hostname + ": " + cookieName(setCookie);
            String lower = setCookie.toLowerCase();
            if (!lower.contains("secure")) {
                findings.add(finding("COOKIE_MISSING_SECURE_FLAG", Severity.MEDIUM, asset, Map.of("cookie", setCookie)));
            }
            if (!lower.contains("httponly")) {
                findings.add(finding("COOKIE_MISSING_HTTPONLY_FLAG", Severity.MEDIUM, asset, Map.of("cookie", setCookie)));
            }
            if (!lower.contains("samesite")) {
                findings.add(finding("COOKIE_MISSING_SAMESITE", Severity.LOW, asset, Map.of("cookie", setCookie)));
            }
        }

        return findings;
    }

    private static void requireHeader(
            List<RawFinding> findings,
            Map<String, String> headers,
            String hostname,
            String headerName,
            String ruleId,
            Severity severity) {
        if (!headers.containsKey(headerName)) {
            findings.add(finding(ruleId, severity, hostname, Map.of()));
        }
    }

    private static String cookieName(String setCookieHeader) {
        int eq = setCookieHeader.indexOf('=');
        int semi = setCookieHeader.indexOf(';');
        int end = semi > 0 ? semi : setCookieHeader.length();
        return eq > 0 && eq < end ? setCookieHeader.substring(0, eq).trim() : setCookieHeader.substring(0, end).trim();
    }

    /**
     * Only judged when HTTPS is known to work for this host (result.https()) - if it doesn't,
     * there is nothing to redirect to and the missing-TLS problem is the TLS module's to report.
     * A 2xx on cleartext is the real finding (the site is fully usable without TLS, so an
     * on-path attacker gets every request a user or bot makes before HSTS ever applies); a
     * redirect whose first hop is to another http:// URL is the weaker shape - one more
     * cleartext round trip, usually an apex-to-www hop that only upgrades on the next one.
     */
    static List<RawFinding> httpsRedirectFindings(String hostname, FetchResult result) {
        FetchResult.PlainHttpProbe plain = result.plainHttp();
        if (plain == null || !result.https()) {
            return List.of();
        }
        if (plain.status() >= 200 && plain.status() < 300) {
            return List.of(finding(
                    "HTTP_NO_HTTPS_REDIRECT", Severity.MEDIUM, hostname, Map.of("httpStatus", plain.status())));
        }
        if (plain.status() >= 300 && plain.status() < 400 && plain.location() != null
                && !plain.location().toLowerCase(Locale.ROOT).startsWith("https://")) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("httpStatus", plain.status());
            evidence.put("location", plain.location());
            return List.of(finding("HTTP_NO_HTTPS_REDIRECT", Severity.LOW, hostname, evidence));
        }
        return List.of();
    }

    private static RawFinding finding(String ruleId, Severity severity, String asset, Map<String, Object> evidence) {
        String[] copy = COPY.get(ruleId);
        return new RawFinding(ruleId, severity, Category.HEADERS, copy[0], copy[1], asset, evidence);
    }

    private static final Map<String, String[]> COPY = Map.ofEntries(
            Map.entry(
                    "HEADER_CSP_MISSING",
                    new String[] {
                        "Missing Content-Security-Policy header",
                        "The response has no Content-Security-Policy header, reducing protection against XSS and data-injection attacks."
                    }),
            Map.entry(
                    "HEADER_XFO_MISSING",
                    new String[] {
                        "Missing X-Frame-Options header",
                        "The response has no X-Frame-Options header, leaving the site potentially vulnerable to clickjacking."
                    }),
            Map.entry(
                    "HEADER_XCTO_MISSING",
                    new String[] {
                        "Missing X-Content-Type-Options header",
                        "The response has no X-Content-Type-Options: nosniff header, allowing browsers to MIME-sniff responses."
                    }),
            Map.entry(
                    "HEADER_REFERRER_POLICY_MISSING",
                    new String[] {
                        "Missing Referrer-Policy header",
                        "The response has no Referrer-Policy header, so the browser default (often full referrer leakage) applies."
                    }),
            Map.entry(
                    "HEADER_PERMISSIONS_POLICY_MISSING",
                    new String[] {
                        "Missing Permissions-Policy header",
                        "The response has no Permissions-Policy header restricting browser feature access (camera, geolocation, etc.)."
                    }),
            Map.entry(
                    "HTTP_NO_HTTPS_REDIRECT",
                    new String[] {
                        "Plain HTTP not redirected to HTTPS",
                        "The site answers on cleartext HTTP without redirecting to HTTPS. Anything a user or client "
                                + "sends before reaching the HTTPS version - and every visit that starts from an http:// "
                                + "link or a typed hostname - is readable and modifiable by anyone on the network path."
                    }),
            Map.entry(
                    "HEADER_SERVER_BANNER_VERBOSE",
                    new String[] {
                        "Verbose server banner",
                        "The Server or X-Powered-By header discloses specific software/version information useful for targeting known vulnerabilities."
                    }),
            Map.entry(
                    "COOKIE_MISSING_SECURE_FLAG",
                    new String[] {
                        "Cookie missing Secure flag",
                        "A cookie was set without the Secure flag, allowing it to be transmitted over unencrypted HTTP."
                    }),
            Map.entry(
                    "COOKIE_MISSING_HTTPONLY_FLAG",
                    new String[] {
                        "Cookie missing HttpOnly flag",
                        "A cookie was set without the HttpOnly flag, making it readable by client-side JavaScript and easier to steal via XSS."
                    }),
            Map.entry(
                    "COOKIE_MISSING_SAMESITE",
                    new String[] {
                        "Cookie missing SameSite attribute",
                        "A cookie was set without a SameSite attribute, offering no baseline CSRF protection from the browser."
                    }));
}
