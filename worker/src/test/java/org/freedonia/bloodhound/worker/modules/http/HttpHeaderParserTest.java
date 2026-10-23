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
    void cspWithUnsafeInline_flaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'");
        FetchResult result = new FetchResult(true, h, List.of());
        List<RawFinding> findings = HttpHeaderParser.parse("example.com", result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HEADER_CSP_WEAK_POLICY");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
            assertThat(f.evidence()).containsEntry("weaknesses", List.of("script-src: unsafe-inline"));
        });
    }

    /**
     * A rules-parity review found unsafe-inline checked against the whole header string,
     * conflating style-src's (inline CSS - common, comparatively low-risk) with script-src's
     * (inline script execution - the actual XSS-relevant weakness this rule exists for).
     */
    @Test
    void cspWithUnsafeInlineOnStyleSrcOnly_notFlaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).doesNotContain("HEADER_CSP_WEAK_POLICY");
    }

    @Test
    void cspWithUnsafeEval_flaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src 'self' 'unsafe-eval'");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).contains("HEADER_CSP_WEAK_POLICY");
    }

    @Test
    void cspWithWildcardScriptSrc_flaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src 'self'; script-src *");
        FetchResult result = new FetchResult(true, h, List.of());
        List<RawFinding> findings = HttpHeaderParser.parse("example.com", result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HEADER_CSP_WEAK_POLICY");
            assertThat(f.evidence()).containsEntry("weaknesses", List.of("script-src: *"));
        });
    }

    @Test
    void cspWithWildcardDefaultSrc_flaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src *");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).contains("HEADER_CSP_WEAK_POLICY");
    }

    /** "img-src *" (any image host) is common and benign - must not be confused with a script-src/default-src wildcard. */
    @Test
    void cspWithWildcardImgSrcOnly_notFlaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "default-src 'self'; img-src *");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).doesNotContain("HEADER_CSP_WEAK_POLICY");
    }

    /** A wildcard subdomain allowance ("*.example.com") is a specific, scoped source, not the bare "any origin" wildcard. */
    @Test
    void cspWithWildcardSubdomainSource_notFlaggedWeakPolicy() {
        Map<String, String> h = allSecureHeaders();
        h.put("content-security-policy", "script-src 'self' *.example.com");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).doesNotContain("HEADER_CSP_WEAK_POLICY");
    }

    @Test
    void strictCsp_notFlaggedWeakPolicy() {
        FetchResult result = new FetchResult(true, allSecureHeaders(), List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).doesNotContain("HEADER_CSP_WEAK_POLICY");
    }

    @Test
    void noCspHeaderAtAll_notFlaggedWeakPolicy_onlyMissing() {
        FetchResult result = new FetchResult(true, Map.of(), List.of());
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids).contains("HEADER_CSP_MISSING").doesNotContain("HEADER_CSP_WEAK_POLICY");
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

    /**
     * A rules-parity review found the old whole-line substring checks could be suppressed by a
     * cookie NAME or VALUE that merely contains the flag's text - none of these three cookies
     * actually set Secure/HttpOnly/SameSite, but their name/value text alone would have hidden
     * that under the old "contains(...)" check.
     */
    @Test
    void cookieNameOrValueContainingFlagText_stillFlaggedAsMissing() {
        FetchResult result = new FetchResult(
                true,
                allSecureHeaders(),
                List.of(
                        "session=secure_abc123",
                        "insecure_mode=httponly_test",
                        "samesite_pref=1"));
        List<String> ids = ruleIds(HttpHeaderParser.parse("example.com", result));
        assertThat(ids)
                .contains("COOKIE_MISSING_SECURE_FLAG", "COOKIE_MISSING_HTTPONLY_FLAG", "COOKIE_MISSING_SAMESITE");
        // Exactly 3 findings per cookie (9 total) - none of them should also have picked up
        // COOKIE_MISSING_HOST_PREFIX, which only applies once Secure is genuinely present.
        assertThat(ids).hasSize(9).doesNotContain("COOKIE_MISSING_HOST_PREFIX");
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

    private static FetchResult withCookie(String setCookie) {
        return new FetchResult(true, allSecureHeaders(), List.of(setCookie));
    }

    @Test
    void cookieDomainScopedToParent_flagged() {
        FetchResult result = withCookie(
                "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=.example.com");
        List<RawFinding> findings = HttpHeaderParser.parse("app.example.com", result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("COOKIE_DOMAIN_TOO_BROAD");
            assertThat(f.severity().name()).isEqualTo("LOW");
            assertThat(f.affectedAsset()).isEqualTo("app.example.com: session_id");
            assertThat(f.evidence()).containsEntry("domain", ".example.com");
        });
    }

    @Test
    void cookieDomainScopedToParentWithoutLeadingDot_stillFlagged() {
        // The leading dot is optional per modern Cookie spec parsing - Domain=example.com means
        // the exact same thing as Domain=.example.com.
        FetchResult result = withCookie(
                "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com");
        assertThat(ruleIds(HttpHeaderParser.parse("app.example.com", result))).contains("COOKIE_DOMAIN_TOO_BROAD");
    }

    @Test
    void cookieDomainMatchingExactHost_notFlagged() {
        // Domain=<the exact same host> is just a verbose way of writing the same host-only scope
        // a missing Domain attribute already gives - not actually broader, not a finding.
        FetchResult result = withCookie(
                "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=app.example.com");
        assertThat(ruleIds(HttpHeaderParser.parse("app.example.com", result))).doesNotContain("COOKIE_DOMAIN_TOO_BROAD");
    }

    @Test
    void cookieWithNoDomainAttribute_notFlagged() {
        FetchResult result = withCookie("session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
        assertThat(ruleIds(HttpHeaderParser.parse("app.example.com", result))).doesNotContain("COOKIE_DOMAIN_TOO_BROAD");
    }

    @Test
    void cookieDomainUnrelatedToHost_notFlaggedAsTooBroad() {
        // A Domain attribute naming some other, unrelated domain entirely isn't "broader than
        // this host" in the parent-domain sense this rule checks - browsers themselves reject a
        // cookie whose Domain doesn't match the setting host at all, so this isn't this rule's
        // signal to raise (a different, structural misconfiguration, not scope-too-broad).
        FetchResult result = withCookie(
                "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=other.net");
        assertThat(ruleIds(HttpHeaderParser.parse("app.example.com", result))).doesNotContain("COOKIE_DOMAIN_TOO_BROAD");
    }

    private static FetchResult withPlainHttp(boolean https, FetchResult.PlainHttpProbe plain) {
        return new FetchResult(https, allSecureHeaders(), List.of(), plain, null);
    }

    private static FetchResult withCors(FetchResult.CorsProbe cors) {
        return new FetchResult(true, allSecureHeaders(), List.of(), null, cors);
    }

    private static FetchResult withTrace(FetchResult.TraceProbe trace) {
        return new FetchResult(true, allSecureHeaders(), List.of(), null, null, trace);
    }

    @Test
    void traceMethodReturns200_flagged() {
        FetchResult result = withTrace(new FetchResult.TraceProbe(200, true));
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).containsExactly("HTTP_TRACE_METHOD_ENABLED");
    }

    @Test
    void traceMethodReturns200_withoutEchoedMarker_stillFlagged() {
        // Not every TRACE implementation echoes the probe's own marker back verbatim, but a bare
        // 200 (rather than 405/501) already confirms the server processes TRACE instead of
        // rejecting it - the real finding, with or without the stronger echo confirmation.
        FetchResult result = withTrace(new FetchResult.TraceProbe(200, false));
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result))).containsExactly("HTTP_TRACE_METHOD_ENABLED");
    }

    @Test
    void traceMethodRejected_notFlagged() {
        FetchResult result = withTrace(new FetchResult.TraceProbe(405, false));
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    @Test
    void traceProbeFailed_null_notFlagged() {
        FetchResult result = withTrace(null);
        assertThat(HttpHeaderParser.parse("example.com", result)).isEmpty();
    }

    private static FetchResult withReferrerPolicy(String value) {
        Map<String, String> h = allSecureHeaders();
        h.put("referrer-policy", value);
        return new FetchResult(true, h, List.of());
    }

    @Test
    void referrerPolicyUnsafeUrl_flagged() {
        List<RawFinding> findings = HttpHeaderParser.parse("example.com", withReferrerPolicy("unsafe-url"));
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HEADER_REFERRER_POLICY_UNSAFE");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
            assertThat(f.evidence()).containsEntry("header", "unsafe-url");
        });
    }

    @Test
    void referrerPolicyUnsafeUrlCaseInsensitive_flagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withReferrerPolicy("Unsafe-URL"))))
                .contains("HEADER_REFERRER_POLICY_UNSAFE");
    }

    @Test
    void referrerPolicyUnsafeUrlAsFallbackEntry_stillFlagged() {
        // Referrer-Policy supports a comma-separated fallback list - unsafe-url anywhere in it
        // means some (older) browser will honor it, not just an exact single-token match.
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withReferrerPolicy("no-referrer, unsafe-url"))))
                .contains("HEADER_REFERRER_POLICY_UNSAFE");
    }

    @Test
    void referrerPolicySafeValue_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withReferrerPolicy("strict-origin-when-cross-origin"))))
                .doesNotContain("HEADER_REFERRER_POLICY_UNSAFE");
    }

    @Test
    void referrerPolicyMissing_notFlaggedAsUnsafe_onlyAsMissing() {
        Map<String, String> h = allSecureHeaders();
        h.remove("referrer-policy");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result)))
                .contains("HEADER_REFERRER_POLICY_MISSING")
                .doesNotContain("HEADER_REFERRER_POLICY_UNSAFE");
    }

    @Test
    void referrerPolicySimilarButNotUnsafeUrlToken_notFlagged() {
        // "unsafe-url" as a value must be matched as a whole token, not a substring - a real (if
        // unlikely) custom/future policy name merely containing it should not false-positive.
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withReferrerPolicy("not-unsafe-url-ish"))))
                .doesNotContain("HEADER_REFERRER_POLICY_UNSAFE");
    }

    private static FetchResult withXcto(String value) {
        Map<String, String> h = allSecureHeaders();
        h.put("x-content-type-options", value);
        return new FetchResult(true, h, List.of());
    }

    @Test
    void xctoInvalidValue_flagged() {
        List<RawFinding> findings = HttpHeaderParser.parse("example.com", withXcto("sniff"));
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("HEADER_XCTO_INVALID_VALUE");
            assertThat(f.severity().name()).isEqualTo("LOW");
            assertThat(f.evidence()).containsEntry("header", "sniff");
        });
        assertThat(ruleIds(findings)).doesNotContain("HEADER_XCTO_MISSING");
    }

    @Test
    void xctoNosniff_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withXcto("nosniff"))))
                .doesNotContain("HEADER_XCTO_INVALID_VALUE");
    }

    @Test
    void xctoNosniffCaseInsensitive_notFlagged() {
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", withXcto("NoSniff"))))
                .doesNotContain("HEADER_XCTO_INVALID_VALUE");
    }

    @Test
    void xctoMissing_flaggedAsMissingNotInvalidValue() {
        Map<String, String> h = allSecureHeaders();
        h.remove("x-content-type-options");
        FetchResult result = new FetchResult(true, h, List.of());
        assertThat(ruleIds(HttpHeaderParser.parse("example.com", result)))
                .contains("HEADER_XCTO_MISSING")
                .doesNotContain("HEADER_XCTO_INVALID_VALUE");
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
