package org.freedonia.bloodhound.worker.modules.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TechDecisionLogicTest {

    private static List<String> names(List<Technology> technologies) {
        return technologies.stream().map(Technology::name).toList();
    }

    @Test
    void noSignatures_producesEmptyList() {
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), "<html><body>hello</body></html>");
        assertThat(TechDecisionLogic.decide(result)).isEmpty();
    }

    @Test
    void nginxServerHeader_isDetected() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "nginx/1.25.3"), List.of(), "");
        List<Technology> found = TechDecisionLogic.decide(result);
        assertThat(names(found)).contains("nginx");
        assertThat(found).anyMatch(t -> t.name().equals("nginx") && t.category().equals(Technology.WEB_SERVER));
    }

    @Test
    void wordpressGeneratorMeta_isDetected() {
        String body = "<html><head><meta name=\"generator\" content=\"WordPress 6.4\"></head></html>";
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), body);
        assertThat(names(TechDecisionLogic.decide(result))).contains("WordPress");
    }

    @Test
    void wordpressCookie_isDetectedEvenWithoutGeneratorMeta() {
        TechFetchResult result = new TechFetchResult(Map.of(), List.of("wordpress_logged_in_abc123=1; Path=/"), "<html></html>");
        assertThat(names(TechDecisionLogic.decide(result))).contains("WordPress");
    }

    @Test
    void phpSessionCookie_isDetected() {
        TechFetchResult result = new TechFetchResult(Map.of(), List.of("PHPSESSID=abc123; Path=/"), "");
        assertThat(names(TechDecisionLogic.decide(result))).contains("PHP");
    }

    @Test
    void cloudflareCfRayHeader_isDetected() {
        TechFetchResult result = new TechFetchResult(Map.of("cf-ray", "8a1b2c-LHR"), List.of(), "");
        assertThat(names(TechDecisionLogic.decide(result))).contains("Cloudflare");
    }

    @Test
    void jqueryAndBootstrapAndGoogleAnalytics_allDetectedTogether() {
        String body = "<script src=\"/js/jquery-3.7.1.min.js\"></script>"
                + "<link rel=\"stylesheet\" href=\"/css/bootstrap.min.css\">"
                + "<script src=\"https://www.google-analytics.com/analytics.js\"></script>";
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), body);
        List<String> found = names(TechDecisionLogic.decide(result));
        assertThat(found).contains("jQuery", "Bootstrap", "Google Analytics");
    }

    @Test
    void duplicateSignalsForSameTechnology_producesOneEntryNotTwo() {
        // Both a generator meta tag and a wp-content path point at WordPress - should still be one entry.
        String body = "<meta name=\"generator\" content=\"WordPress 6.4\"><img src=\"/wp-content/uploads/x.png\">";
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), body);
        List<Technology> found = TechDecisionLogic.decide(result);
        assertThat(found.stream().filter(t -> t.name().equals("WordPress")).count()).isEqualTo(1);
    }

    @Test
    void reactAndNextJs_bothDetected() {
        String body = "<div data-reactroot=\"\"></div><script id=\"__NEXT_DATA__\" type=\"application/json\">{}</script>";
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), body);
        assertThat(names(TechDecisionLogic.decide(result))).contains("React", "Next.js");
    }

    @Test
    void nginxServerHeader_versionIsCaptured() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "nginx/1.31.4"), List.of(), "");
        Technology nginx = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("nginx"))
                .findFirst()
                .orElseThrow();
        assertThat(nginx.version()).isEqualTo("1.31.4");
    }

    @Test
    void apacheServerHeader_versionCapturedIgnoringTrailingPlatformText() {
        // Real-world Server headers commonly trail with platform info the version regex must not swallow.
        TechFetchResult result = new TechFetchResult(Map.of("server", "Apache/2.4.58 (Ubuntu)"), List.of(), "");
        Technology apache = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("Apache"))
                .findFirst()
                .orElseThrow();
        assertThat(apache.version()).isEqualTo("2.4.58");
    }

    @Test
    void phpXPoweredByHeader_versionIsCaptured() {
        TechFetchResult result =
                new TechFetchResult(Map.of("x-powered-by", "PHP/7.4.33"), List.of(), "");
        Technology php = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("PHP"))
                .findFirst()
                .orElseThrow();
        assertThat(php.version()).isEqualTo("7.4.33");
    }

    @Test
    void wordpressGeneratorMeta_versionIsCaptured() {
        String body = "<html><head><meta name=\"generator\" content=\"WordPress 6.4.2\"></head></html>";
        TechFetchResult result = new TechFetchResult(Map.of(), List.of(), body);
        Technology wp = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("WordPress"))
                .findFirst()
                .orElseThrow();
        assertThat(wp.version()).isEqualTo("6.4.2");
    }

    @Test
    void versionAbsent_leavesVersionNullRatherThanThrowing() {
        // A bare "nginx" Server header with no version suffix is a real, common case (some
        // operators deliberately strip it) - must not throw, just report no version.
        TechFetchResult result = new TechFetchResult(Map.of("server", "nginx"), List.of(), "");
        Technology nginx = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("nginx"))
                .findFirst()
                .orElseThrow();
        assertThat(nginx.version()).isNull();
    }

    @Test
    void cookieOnlyPhpDetection_hasNoVersion() {
        // PHP detected only via PHPSESSID (no Server/X-Powered-By signal) genuinely has no
        // version signal available - confirms the plain addIf path still yields version=null.
        TechFetchResult result = new TechFetchResult(Map.of(), List.of("PHPSESSID=abc123; Path=/"), "");
        Technology php = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("PHP"))
                .findFirst()
                .orElseThrow();
        assertThat(php.version()).isNull();
    }
}
