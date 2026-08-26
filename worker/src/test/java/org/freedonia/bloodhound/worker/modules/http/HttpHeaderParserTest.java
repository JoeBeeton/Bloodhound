package org.freedonia.bloodhound.worker.modules.http;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class HttpHeaderParserTest {

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    private static Map<String, String> allSecureHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("content-security-policy", "default-src 'self'");
        h.put("x-frame-options", "DENY");
        h.put("x-content-type-options", "nosniff");
        h.put("referrer-policy", "strict-origin-when-cross-origin");
        h.put("permissions-policy", "geolocation=()");
        h.put("server", "cloudflare");
        return h;
    }

    @Test
    void allHeadersPresent_noCookies_producesNoFindings() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of());
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void allHeadersMissing_flagsAllFiveHeaderRules() {
        FetchResult result = new FetchResult(true, Map.of(), List.of());
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids)
                .contains(
                        "HEADER_CSP_MISSING",
                        "HEADER_XFO_MISSING",
                        "HEADER_XCTO_MISSING",
                        "HEADER_REFERRER_POLICY_MISSING",
                        "HEADER_PERMISSIONS_POLICY_MISSING");
    }

    @Test
    void verboseServerBanner_withVersionNumber_isFlagged() {
        Map<String, String> h = allSecureHeaders();
        h.put("server", "Apache/2.4.41 (Ubuntu)");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).contains("HEADER_SERVER_BANNER_VERBOSE");
    }

    @Test
    void bareServerBanner_withoutVersion_isNotFlagged() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).doesNotContain("HEADER_SERVER_BANNER_VERBOSE");
    }

    @Test
    void cookieMissingAllFlags_flagsAllThreeCookieRules() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of("session_id=abc123; Path=/"));
        List<RawFinding> findings = HttpHeaderParser.parse("example.com", result);
        assertThat(findings)
                .extracting(RawFinding::ruleId)
                .contains("COOKIE_MISSING_SECURE_FLAG", "COOKIE_MISSING_HTTPONLY_FLAG", "COOKIE_MISSING_SAMESITE");
        // Asset is "hostname: cookie-name", not just the cookie name - this
        // module now scans a target's subdomains too, and several hosts can
        // legitimately set same-named cookies, so the hostname must stay in
        // the asset to keep findings from colliding under central-server's
        // (target_id, rule_id, affected_asset) dedup key.
        assertThat(findings).extracting(RawFinding::affectedAsset).contains("example.com: session_id");
    }

    @Test
    void cookieFindingsFromDifferentHosts_haveDistinctAssets() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of("session_id=abc123; Path=/"));
        List<RawFinding> rootFindings = HttpHeaderParser.parse("example.com", result);
        List<RawFinding> subdomainFindings = HttpHeaderParser.parse("portal.example.com", result);
        assertThat(rootFindings)
                .extracting(RawFinding::affectedAsset)
                .contains("example.com: session_id")
                .doesNotContain("portal.example.com: session_id");
        assertThat(subdomainFindings)
                .extracting(RawFinding::affectedAsset)
                .contains("portal.example.com: session_id")
                .doesNotContain("example.com: session_id");
    }

    @Test
    void cookieWithAllFlags_flagsNothing() {
        FetchResult result = new FetchResult(
                true, allSecureHeaders(), List.of("session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"));
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void cookiePartiallyFlagged_onlyMissingAttributeReported() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of("session_id=abc123; Secure; HttpOnly"));
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids).containsExactly("COOKIE_MISSING_SAMESITE");
    }
}
