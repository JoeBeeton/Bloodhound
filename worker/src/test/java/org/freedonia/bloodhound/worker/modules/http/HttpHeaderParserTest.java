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
        h.put("cross-origin-opener-policy", "same-origin");
        h.put("cross-origin-resource-policy", "same-origin");
        h.put("server", "cloudflare");
        return h;
    }

    @Test
    void allHeadersPresent_noCookies_producesNoFindings() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of());
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void allHeadersMissing_flagsAllSevenHeaderRules() {
        FetchResult result = new FetchResult(true, Map.of(), List.of());
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids)
                .contains(
                        "HEADER_CSP_MISSING",
                        "HEADER_XFO_MISSING",
                        "HEADER_XCTO_MISSING",
                        "HEADER_REFERRER_POLICY_MISSING",
                        "HEADER_PERMISSIONS_POLICY_MISSING",
                        "HEADER_COOP_MISSING",
                        "HEADER_CORP_MISSING");
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
                true, allSecureHeaders(), List.of("__Host-session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"));
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void cookiePartiallyFlagged_onlyMissingAttributeReported() {
        FetchResult result =
                new FetchResult(true, allSecureHeaders(), List.of("__Host-session_id=abc123; Secure; HttpOnly"));
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids).containsExactly("COOKIE_MISSING_SAMESITE");
    }

    @Test
    void secureCookieWithoutHostOrSecurePrefix_flagged() {
        FetchResult result = new FetchResult(
                true, allSecureHeaders(), List.of("session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"));
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).containsExactly("COOKIE_MISSING_HOST_PREFIX");
    }

    @Test
    void secureCookieWithSecurePrefix_notFlagged() {
        FetchResult result = new FetchResult(
                true, allSecureHeaders(), List.of("__Secure-session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"));
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void nonSecureCookieMissingPrefix_notDoubleFlagged() {
        // Missing Secure entirely is already COOKIE_MISSING_SECURE_FLAG's job - the prefix check
        // only applies once Secure is present, so this shouldn't also produce a redundant
        // COOKIE_MISSING_HOST_PREFIX finding.
        FetchResult result =
                new FetchResult(true, allSecureHeaders(), List.of("session_id=abc123; HttpOnly; SameSite=Lax"));
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).containsExactly("COOKIE_MISSING_SECURE_FLAG");
    }

    private static FetchResult withPlainHttp(boolean https, FetchResult.PlainHttpProbe plain) {
        return new FetchResult(https, allSecureHeaders(), List.of(), plain, null);
    }

    private static FetchResult withCors(FetchResult.CorsProbe cors) {
        return new FetchResult(true, allSecureHeaders(), List.of(), null, cors);
    }

    @Test
    void contentServedOverCleartext_flaggedMedium() {
        List<RawFinding> findings = HttpHeaderParser.parse(
                "example.com", withPlainHttp(true, new FetchResult.PlainHttpProbe(200, null)));
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HTTP_NO_HTTPS_REDIRECT");
            assertThat(f.severity()).isEqualTo(org.freedonia.bloodhound.common.findings.Severity.MEDIUM);
            assertThat(f.evidence()).containsEntry("httpStatus", 200);
        });
    }

    @Test
    void firstHopRedirectsToAnotherCleartextUrl_flaggedLow() {
        List<RawFinding> findings = HttpHeaderParser.parse(
                "example.com", withPlainHttp(true, new FetchResult.PlainHttpProbe(301, "http://www.example.com/")));
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HTTP_NO_HTTPS_REDIRECT");
            assertThat(f.severity()).isEqualTo(org.freedonia.bloodhound.common.findings.Severity.LOW);
            assertThat(f.evidence()).containsEntry("location", "http://www.example.com/");
        });
    }

    @Test
    void redirectStraightToHttps_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withPlainHttp(true, new FetchResult.PlainHttpProbe(301, "https://example.com/")))))
                .doesNotContain("HTTP_NO_HTTPS_REDIRECT");
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withPlainHttp(true, new FetchResult.PlainHttpProbe(308, "HTTPS://Example.com/x")))))
                .doesNotContain("HTTP_NO_HTTPS_REDIRECT");
    }

    /** Nothing on port 80 is the ideal; HTTPS-unreachable is the TLS module's problem; errors say nothing. */
    @Test
    void noCleartextListener_orNoHttps_orErrorStatus_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withPlainHttp(true, null))))
                .doesNotContain("HTTP_NO_HTTPS_REDIRECT");
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withPlainHttp(false, new FetchResult.PlainHttpProbe(200, null)))))
                .doesNotContain("HTTP_NO_HTTPS_REDIRECT");
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withPlainHttp(true, new FetchResult.PlainHttpProbe(403, null)))))
                .doesNotContain("HTTP_NO_HTTPS_REDIRECT");
    }

    @Test
    void corsReflectsProbeOriginWithCredentials_flaggedHigh() {
        List<RawFinding> findings = HttpHeaderParser.parse(
                "example.com",
                withCors(new FetchResult.CorsProbe(HttpHeaderFetcher.CORS_PROBE_ORIGIN, "true")));
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("CORS_CREDENTIALED_ORIGIN_REFLECTION");
            assertThat(f.severity()).isEqualTo(org.freedonia.bloodhound.common.findings.Severity.HIGH);
            assertThat(f.evidence()).containsEntry("allowOrigin", HttpHeaderFetcher.CORS_PROBE_ORIGIN);
        });
    }

    @Test
    void corsReflectsOriginCaseInsensitively_stillFlagged() {
        List<RawFinding> findings = HttpHeaderParser.parse(
                "example.com",
                withCors(new FetchResult.CorsProbe(HttpHeaderFetcher.CORS_PROBE_ORIGIN.toUpperCase(), "TRUE")));
        assertThat(ruleIds(findings)).contains("CORS_CREDENTIALED_ORIGIN_REFLECTION");
    }

    /** A bare wildcard can never carry credentials per the CORS spec itself - not the same attack, not flagged. */
    @Test
    void corsWildcardWithoutCredentials_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withCors(new FetchResult.CorsProbe("*", null)))))
                .doesNotContain("CORS_CREDENTIALED_ORIGIN_REFLECTION");
    }

    /** Reflects the probe origin, but never actually sends credentials:true - not exploitable the same way. */
    @Test
    void corsReflectsOriginButNoCredentialsHeader_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withCors(new FetchResult.CorsProbe(HttpHeaderFetcher.CORS_PROBE_ORIGIN, null)))))
                .doesNotContain("CORS_CREDENTIALED_ORIGIN_REFLECTION");
    }

    /** A specific, real allowlisted origin with credentials:true is a deliberate, legitimate config, not a reflection. */
    @Test
    void corsAllowsOneRealOriginWithCredentials_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse(
                        "example.com", withCors(new FetchResult.CorsProbe("https://app.example.com", "true")))))
                .doesNotContain("CORS_CREDENTIALED_ORIGIN_REFLECTION");
    }

    @Test
    void noCorsProbeResult_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withCors(null))))
                .doesNotContain("CORS_CREDENTIALED_ORIGIN_REFLECTION");
    }
}
