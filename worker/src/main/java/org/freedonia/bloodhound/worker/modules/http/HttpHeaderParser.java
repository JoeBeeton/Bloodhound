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
        findings.addAll(cspWeakPolicyFindings(hostname, headers.get("content-security-policy")));
        requireHeader(findings, headers, hostname, "x-frame-options", "HEADER_XFO_MISSING", Severity.LOW);
        requireHeader(findings, headers, hostname, "x-content-type-options", "HEADER_XCTO_MISSING", Severity.LOW);
        findings.addAll(xctoInvalidValueFindings(hostname, headers.get("x-content-type-options")));
        requireHeader(findings, headers, hostname, "referrer-policy", "HEADER_REFERRER_POLICY_MISSING", Severity.INFO);
        findings.addAll(referrerPolicyUnsafeFindings(hostname, headers.get("referrer-policy")));
        requireHeader(
                findings, headers, hostname, "permissions-policy", "HEADER_PERMISSIONS_POLICY_MISSING", Severity.INFO);
        requireHeader(
                findings, headers, hostname, "cross-origin-opener-policy", "HEADER_COOP_MISSING", Severity.INFO);
        requireHeader(
                findings, headers, hostname, "cross-origin-resource-policy", "HEADER_CORP_MISSING", Severity.INFO);

        findings.addAll(httpsRedirectFindings(hostname, result));
        findings.addAll(corsReflectionFindings(hostname, result));
        findings.addAll(traceMethodFindings(hostname, result));

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
            // A rules-parity review found the old whole-line substring checks
            // (lower.contains("secure") etc.) could be suppressed by a cookie NAME or VALUE that
            // merely happens to contain the flag's text - e.g. "session=secure_abc123; HttpOnly"
            // (no actual Secure attribute) or "insecure_flag=1; Secure" (the real attribute IS
            // present, but even the fixed case would've gotten lucky there) - matched by
            // hasCookieAttribute below, which only looks at the ;-separated attribute list after
            // the cookie's own name=value pair, not the whole raw header line.
            boolean hasSecure = hasCookieAttribute(setCookie, "secure");
            if (!hasSecure) {
                findings.add(finding("COOKIE_MISSING_SECURE_FLAG", Severity.MEDIUM, asset, Map.of("cookie", setCookie)));
            }
            if (!hasCookieAttribute(setCookie, "httponly")) {
                findings.add(finding("COOKIE_MISSING_HTTPONLY_FLAG", Severity.MEDIUM, asset, Map.of("cookie", setCookie)));
            }
            if (!hasCookieAttribute(setCookie, "samesite")) {
                findings.add(finding("COOKIE_MISSING_SAMESITE", Severity.LOW, asset, Map.of("cookie", setCookie)));
            }
            // Only worth flagging once Secure is already present - a cookie missing Secure
            // entirely is already covered by COOKIE_MISSING_SECURE_FLAG above, and neither
            // prefix is valid without it anyway. __Host- (Secure + Path=/ + no Domain) is the
            // stronger of the two - the browser refuses to even accept a same-named cookie set
            // by a subdomain - but __Secure- alone is still worth crediting as a step up from a
            // bare Secure cookie.
            if (hasSecure) {
                String name = cookieName(setCookie);
                if (!name.startsWith("__Host-") && !name.startsWith("__Secure-")) {
                    findings.add(finding(
                            "COOKIE_MISSING_HOST_PREFIX", Severity.INFO, asset, Map.of("cookie", setCookie)));
                }
            }
            findings.addAll(cookieDomainTooBroadFindings(hostname, asset, setCookie));
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
     * True iff one of this cookie's {@code ;}-separated attributes (never the leading
     * name=value pair at index 0, which is not an attribute and could coincidentally contain the
     * flag's own text in the cookie's name or value) has this exact key, case-insensitive -
     * matches both a bare boolean flag ("Secure") and a valued one ("SameSite=Lax").
     */
    private static boolean hasCookieAttribute(String setCookieHeader, String attributeName) {
        String[] parts = setCookieHeader.split(";");
        for (int i = 1; i < parts.length; i++) {
            String trimmed = parts[i].trim();
            int eq = trimmed.indexOf('=');
            String key = (eq >= 0 ? trimmed.substring(0, eq) : trimmed).trim();
            if (key.equalsIgnoreCase(attributeName)) {
                return true;
            }
        }
        return false;
    }

    private static String cookieDomainAttribute(String setCookieHeader) {
        for (String part : setCookieHeader.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase(Locale.ROOT).startsWith("domain=")) {
                return trimmed.substring("domain=".length()).trim();
            }
        }
        return null;
    }

    /**
     * No Domain attribute at all is the safest default (RFC 6265 host-only cookie - sent back
     * only to the exact host that set it). Explicitly setting Domain to a PARENT of the scanned
     * host broadens that scope to every subdomain, not just this one - the same subdomains this
     * product's own SUBDOMAIN_DANGLING_CNAME/SUBDOMAIN_NS_DELEGATION_TAKEOVER checks already flag
     * as a real attacker foothold risk: a cookie scoped this broadly is sent to (and, without
     * HttpOnly, readable by script running on) any one of them, including one that's since been
     * abandoned and retaken over. Domain=exact-same-host is NOT flagged - that's just a verbose
     * way of writing the same host-only scope a missing Domain attribute already gives.
     */
    static List<RawFinding> cookieDomainTooBroadFindings(String hostname, String asset, String setCookieHeader) {
        String domainAttr = cookieDomainAttribute(setCookieHeader);
        if (domainAttr == null) {
            return List.of();
        }
        String normalized = domainAttr.startsWith(".") ? domainAttr.substring(1) : domainAttr;
        if (normalized.isEmpty() || normalized.equalsIgnoreCase(hostname)) {
            return List.of();
        }
        if (!hostname.toLowerCase(Locale.ROOT).endsWith("." + normalized.toLowerCase(Locale.ROOT))) {
            return List.of();
        }
        return List.of(finding(
                "COOKIE_DOMAIN_TOO_BROAD",
                Severity.LOW,
                asset,
                Map.of("cookie", setCookieHeader, "domain", domainAttr)));
    }

    /**
     * CSP's own presence (HEADER_CSP_MISSING, checked separately above) says nothing about
     * whether the policy actually does anything - Mozilla Observatory's own CSP grading
     * specifically downgrades a policy containing 'unsafe-inline'/'unsafe-eval' (both defeat most
     * of CSP's real XSS-mitigation value: 'unsafe-inline' lets any injected inline &lt;script&gt;
     * run exactly as if there were no policy at all) or a bare wildcard source (* - any origin,
     * not just ones the site actually trusts). A gap this module had: only presence was checked,
     * never policy quality.
     */
    /**
     * A rules-parity review found unsafe-inline/unsafe-eval checked against the WHOLE header
     * string, conflating "style-src 'unsafe-inline'" (inline CSS - a common, comparatively low-
     * risk allowance plenty of legitimate sites use) with "script-src 'unsafe-inline'" (inline
     * script execution - the actual XSS-relevant weakness). A policy with ONLY the former would
     * be flagged exactly as if it allowed arbitrary inline script. Fixed the same way the
     * existing per-directive "*" check already works below: split on ';' and look at each
     * directive's own value list, scoped to the directives that actually control script
     * execution (script-src, default-src as its fallback) - never style-src.
     */
    static List<RawFinding> cspWeakPolicyFindings(String hostname, String cspHeaderValue) {
        if (cspHeaderValue == null) {
            return List.of();
        }
        List<String> weaknesses = new ArrayList<>();
        for (String directive : cspHeaderValue.split(";")) {
            String trimmed = directive.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split("\\s+");
            String directiveName = parts[0].toLowerCase(Locale.ROOT);
            if (!directiveName.equals("script-src") && !directiveName.equals("default-src")) {
                continue;
            }
            for (int i = 1; i < parts.length; i++) {
                String value = parts[i];
                // "img-src *" is a common, low-risk allowance (any image host) and must not be
                // confused with "script-src *"/"default-src *" (any script from anywhere) - a
                // bare "*" token, not "*.example.com", a legitimate wildcard subdomain allowance.
                if (value.equals("*")) {
                    weaknesses.add(directiveName + ": *");
                } else if (value.equals("'unsafe-inline'")) {
                    weaknesses.add(directiveName + ": unsafe-inline");
                } else if (value.equals("'unsafe-eval'")) {
                    weaknesses.add(directiveName + ": unsafe-eval");
                }
            }
        }
        if (weaknesses.isEmpty()) {
            return List.of();
        }
        return List.of(finding(
                "HEADER_CSP_WEAK_POLICY",
                Severity.MEDIUM,
                hostname,
                Map.of("header", cspHeaderValue, "weaknesses", weaknesses)));
    }

    /**
     * HEADER_REFERRER_POLICY_MISSING (checked separately above) only judges presence - it says
     * nothing about whether the policy that IS set actually protects anything. {@code unsafe-url}
     * is the worst possible value: it sends the complete referrer URL - full path and query
     * string, which routinely carries session tokens, API keys, search terms, or other PII - on
     * every single navigation, including cross-origin requests and HTTPS-to-HTTP downgrades where
     * every other policy value withholds at least the path. Referrer-Policy supports a
     * comma-separated fallback list (older browsers honor an earlier, more-supported entry), so
     * this checks for the token anywhere in the value, not just an exact match on the whole header.
     */
    static List<RawFinding> referrerPolicyUnsafeFindings(String hostname, String referrerPolicyHeaderValue) {
        if (referrerPolicyHeaderValue == null) {
            return List.of();
        }
        boolean unsafe = java.util.Arrays.stream(referrerPolicyHeaderValue.split(","))
                .map(String::trim)
                .anyMatch(token -> token.equalsIgnoreCase("unsafe-url"));
        if (!unsafe) {
            return List.of();
        }
        return List.of(finding(
                "HEADER_REFERRER_POLICY_UNSAFE",
                Severity.MEDIUM,
                hostname,
                Map.of("header", referrerPolicyHeaderValue)));
    }

    /**
     * X-Content-Type-Options recognizes exactly one value: {@code nosniff}. Anything else - a
     * typo, a stray duplicate, a copy-pasted garbage value - is silently ignored by every
     * browser, which makes it functionally identical to HEADER_XCTO_MISSING (checked separately
     * above as presence only) while looking, to a human skimming raw headers, like it's set
     * correctly. Both Mozilla Observatory and securityheaders.com check the value, not just
     * presence, for exactly this reason.
     */
    static List<RawFinding> xctoInvalidValueFindings(String hostname, String xctoHeaderValue) {
        if (xctoHeaderValue == null || xctoHeaderValue.trim().equalsIgnoreCase("nosniff")) {
            return List.of();
        }
        return List.of(finding("HEADER_XCTO_INVALID_VALUE", Severity.LOW, hostname, Map.of("header", xctoHeaderValue)));
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

    /**
     * A fabricated, definitely-not-a-real-allowlisted Origin (see {@link
     * HttpHeaderFetcher#CORS_PROBE_ORIGIN}) coming back verbatim in Access-Control-Allow-Origin,
     * combined with Access-Control-Allow-Credentials: true, means the server reflects whatever
     * Origin it's handed rather than checking it against a real allowlist - any malicious site
     * can then make authenticated cross-origin requests using a logged-in victim's cookies and
     * read the response. A bare wildcard ({@code *}) is deliberately NOT flagged here: browsers
     * refuse to send credentials to a wildcard origin regardless of the credentials header (the
     * CORS spec forbids the combination), so it can't enable the same attack, and an
     * unauthenticated public API returning {@code *} is extremely common and not itself a
     * misconfiguration worth an org-wide finding.
     */
    static List<RawFinding> corsReflectionFindings(String hostname, FetchResult result) {
        FetchResult.CorsProbe cors = result.cors();
        if (cors == null || cors.allowOrigin() == null) {
            return List.of();
        }
        boolean reflected = cors.allowOrigin().equalsIgnoreCase(HttpHeaderFetcher.CORS_PROBE_ORIGIN);
        boolean credentialed = "true".equalsIgnoreCase(cors.allowCredentials());
        if (reflected && credentialed) {
            return List.of(finding(
                    "CORS_CREDENTIALED_ORIGIN_REFLECTION",
                    Severity.HIGH,
                    hostname,
                    Map.of("allowOrigin", cors.allowOrigin(), "allowCredentials", cors.allowCredentials())));
        }
        return List.of();
    }

    /**
     * RFC 7231 2.1 documents TRACE's own purpose as a diagnostic loop-back: the server echoes the
     * request back verbatim as the response body. A server that processes it at all (rather than
     * answering 405/501 like a hardened one should) enables Cross-Site Tracing (XST) - combined
     * with an otherwise-HttpOnly cookie and a same-site XSS/CSRF primitive elsewhere, XST lets an
     * attacker's script read the cookie back out of the echoed request anyway, bypassing
     * HttpOnly's one protection. Every major scanner (Nessus, Qualys, Nikto) still checks this as
     * a baseline hardening item even though most current browsers block TRACE from
     * fetch()/XHR - the method being enabled at all is still the gap worth flagging, not the
     * (now largely closed) exploitation path.
     */
    static List<RawFinding> traceMethodFindings(String hostname, FetchResult result) {
        FetchResult.TraceProbe trace = result.trace();
        if (trace == null || trace.statusCode() != 200) {
            return List.of();
        }
        return List.of(finding(
                "HTTP_TRACE_METHOD_ENABLED",
                Severity.MEDIUM,
                hostname,
                Map.of("statusCode", trace.statusCode(), "echoedRequest", trace.echoedMarker())));
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
                    "HEADER_CSP_WEAK_POLICY",
                    new String[] {
                        "Content-Security-Policy allows unsafe or unrestricted script execution",
                        "A Content-Security-Policy header is present, but its script-src/default-src directive "
                                + "allows 'unsafe-inline', 'unsafe-eval', or a bare wildcard (*) source - each of "
                                + "which defeats most of CSP's real protection against injected-script attacks. A "
                                + "policy with 'unsafe-inline' lets an attacker-injected inline <script> run exactly "
                                + "as if no policy were set at all."
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
                    "HEADER_XCTO_INVALID_VALUE",
                    new String[] {
                        "X-Content-Type-Options set to an invalid value",
                        "The X-Content-Type-Options header is present, but its value isn't nosniff - the only value "
                                + "browsers recognize. Any other value is silently ignored, leaving the response just "
                                + "as open to MIME-sniffing as if the header were missing entirely."
                    }),
            Map.entry(
                    "HEADER_REFERRER_POLICY_MISSING",
                    new String[] {
                        "Missing Referrer-Policy header",
                        "The response has no Referrer-Policy header, so the browser default (often full referrer leakage) applies."
                    }),
            Map.entry(
                    "HEADER_REFERRER_POLICY_UNSAFE",
                    new String[] {
                        "Referrer-Policy set to unsafe-url",
                        "A Referrer-Policy header is present, but its value is (or falls back to) unsafe-url - the "
                                + "worst possible setting. It sends the complete referrer URL, including the full "
                                + "path and query string (which routinely carries session tokens, API keys, or "
                                + "other sensitive data), on every navigation: cross-origin requests and even "
                                + "HTTPS-to-HTTP downgrades, where every other policy value withholds at least the "
                                + "path."
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
                    "CORS_CREDENTIALED_ORIGIN_REFLECTION",
                    new String[] {
                        "CORS reflects arbitrary Origin with credentials allowed",
                        "The server echoes back whatever Origin header it receives in Access-Control-Allow-Origin "
                                + "while also sending Access-Control-Allow-Credentials: true, rather than checking the "
                                + "Origin against a real allowlist. Any malicious website can exploit this to make "
                                + "authenticated cross-origin requests using a logged-in victim's own cookies and read "
                                + "the response."
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
                    }),
            Map.entry(
                    "HEADER_COOP_MISSING",
                    new String[] {
                        "Missing Cross-Origin-Opener-Policy header",
                        "The response has no Cross-Origin-Opener-Policy header, leaving the page's window open to "
                                + "being referenced by cross-origin popups/tabs it opens - a prerequisite for several "
                                + "browser side-channel attacks (e.g. Spectre-style cross-origin data leaks)."
                    }),
            Map.entry(
                    "HEADER_CORP_MISSING",
                    new String[] {
                        "Missing Cross-Origin-Resource-Policy header",
                        "The response has no Cross-Origin-Resource-Policy header, so this resource can be loaded "
                                + "cross-origin (e.g. embedded via <script>/<img>) by any other site without an explicit opt-out."
                    }),
            Map.entry(
                    "COOKIE_MISSING_HOST_PREFIX",
                    new String[] {
                        "Cookie not using __Host-/__Secure- name prefix",
                        "A cookie sets the Secure flag but its name doesn't use the __Host- or __Secure- prefix. "
                                + "These prefixes get the browser itself to enforce the cookie's security properties "
                                + "(__Host- additionally blocks it from being overwritten by a subdomain or a "
                                + "non-root path) rather than relying solely on attributes a misconfiguration could drop."
                    }),
            Map.entry(
                    "COOKIE_DOMAIN_TOO_BROAD",
                    new String[] {
                        "Cookie scoped to a parent domain, not just this host",
                        "A cookie sets its Domain attribute to a parent of the host that set it, broadening the "
                                + "cookie's scope to every subdomain rather than just this one (the default, safer "
                                + "behavior when Domain is left out entirely). The cookie is sent to - and, without "
                                + "HttpOnly, readable by script running on - any one of those subdomains, including "
                                + "one that has since been abandoned or taken over."
                    }),
            Map.entry(
                    "HTTP_TRACE_METHOD_ENABLED",
                    new String[] {
                        "HTTP TRACE method enabled",
                        "The server processes HTTP TRACE requests instead of rejecting them (405/501), echoing the "
                                + "request back as the response body. This enables Cross-Site Tracing (XST): combined "
                                + "with a cross-site scripting or CSRF primitive elsewhere on the site, TRACE lets an "
                                + "attacker's script read back a cookie's value even when that cookie is marked "
                                + "HttpOnly, by echoing the request headers that carried it."
                    }));
}
