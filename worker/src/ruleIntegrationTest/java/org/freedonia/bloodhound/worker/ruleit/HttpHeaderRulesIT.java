package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.http.HttpHeaderModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/** Header rules are mutually exclusive across two hosts: a missing CSP is not a weak CSP. */
@ExtendWith(RuleFixture.class)
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class HttpHeaderRulesIT {

    @Test
    void missingSecurityHeadersCookiesCorsTraceAndBanner() throws Exception {
        ModuleResult result = ScanSupport.run(new HttpHeaderModule(), FixtureHosts.HEADERS_MISSING);
        ScanSupport.assertRules(
                result,
                "HEADER_CSP_MISSING",
                "HEADER_XFO_MISSING",
                "HEADER_XCTO_MISSING",
                "HEADER_REFERRER_POLICY_MISSING",
                "HEADER_PERMISSIONS_POLICY_MISSING",
                "HEADER_COOP_MISSING",
                "HEADER_CORP_MISSING",
                "HTTP_NO_HTTPS_REDIRECT",
                "CORS_CREDENTIALED_ORIGIN_REFLECTION",
                "HTTP_TRACE_METHOD_ENABLED",
                "HEADER_SERVER_BANNER_VERBOSE",
                "COOKIE_MISSING_SECURE_FLAG",
                "COOKIE_MISSING_HTTPONLY_FLAG",
                "COOKIE_MISSING_SAMESITE",
                "COOKIE_MISSING_HOST_PREFIX");
        ScanSupport.assertAbsent(result, "HEADER_CSP_WEAK_POLICY");
        ScanSupport.assertAsset(result, "COOKIE_MISSING_SECURE_FLAG", FixtureHosts.HEADERS_MISSING + ": session");
        ScanSupport.assertAsset(result, "COOKIE_MISSING_HOST_PREFIX", FixtureHosts.HEADERS_MISSING + ": auth");
        assertThat(ScanSupport.ruleIds(result))
                .filteredOn("COOKIE_MISSING_SECURE_FLAG"::equals)
                .hasSize(1);
    }

    @Test
    void weakCspDoesNotAlsoReportMissingCsp() throws Exception {
        ModuleResult result = ScanSupport.run(new HttpHeaderModule(), FixtureHosts.HEADERS_CSP);
        ScanSupport.assertRules(result, "HEADER_CSP_WEAK_POLICY");
        ScanSupport.assertAbsent(
                result,
                "HEADER_CSP_MISSING",
                "HEADER_XFO_MISSING",
                "HEADER_XCTO_MISSING",
                "HEADER_REFERRER_POLICY_MISSING",
                "HEADER_PERMISSIONS_POLICY_MISSING",
                "HEADER_COOP_MISSING",
                "HEADER_CORP_MISSING",
                "HTTP_NO_HTTPS_REDIRECT",
                "CORS_CREDENTIALED_ORIGIN_REFLECTION",
                "HTTP_TRACE_METHOD_ENABLED",
                "HEADER_SERVER_BANNER_VERBOSE",
                "COOKIE_MISSING_SECURE_FLAG",
                "COOKIE_MISSING_HTTPONLY_FLAG",
                "COOKIE_MISSING_SAMESITE",
                "COOKIE_MISSING_HOST_PREFIX");
    }
}
