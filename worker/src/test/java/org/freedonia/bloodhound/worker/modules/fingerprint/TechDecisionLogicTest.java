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

    @Test
    void jqueryVersionCapturedFromFilename() {
        String body = "<script src=\"/js/jquery-3.7.1.min.js\"></script>";
        Technology jquery = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("jQuery"))
                .findFirst()
                .orElseThrow();
        assertThat(jquery.version()).isEqualTo("3.7.1");
    }

    @Test
    void jqueryVersionCapturedFromWordPressEnqueueQueryString() {
        String body = "<script src=\"/wp-includes/js/jquery/jquery.min.js?ver=3.6.0\"></script>";
        Technology jquery = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("jQuery"))
                .findFirst()
                .orElseThrow();
        assertThat(jquery.version()).isEqualTo("3.6.0");
    }

    @Test
    void bootstrapVersionCapturedFromCdnPath() {
        String body = "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\">";
        Technology bootstrap = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("Bootstrap"))
                .findFirst()
                .orElseThrow();
        assertThat(bootstrap.version()).isEqualTo("5.3.0");
    }

    @Test
    void wordPressDetectedViaCanonicalRedirectHeaderAloneEvenWithNoOtherSignal() {
        // Confirmed live: a real target's destination page had zero WordPress signal at all
        // (no generator tag, no wp-content reference) - X-Redirect-By on the redirect itself
        // was the only thing that gave it away. Case-insensitive: the header value on the
        // wire was "WordPress", not "wordpress".
        TechFetchResult result = new TechFetchResult(Map.of("x-redirect-by", "WordPress"), List.of(), "<html></html>");
        assertThat(names(TechDecisionLogic.decide(result))).contains("WordPress");
    }

    @Test
    void bootstrapVersionNotFalselyExtractedFromUnrelatedVendorFilename() {
        // Real bug, caught against a live target: Trustpilot's own widget-init script is
        // literally named "tp.widget.bootstrap.min.js?ver=1.0" - "bootstrap" there is
        // Trustpilot's own naming (bootstrapping/initializing their widget), nothing to do
        // with Twitter Bootstrap. Must not be reported as "Bootstrap 1.0".
        String body = "<script src=\"//widget.trustpilot.com/bootstrap/v5/tp.widget.bootstrap.min.js?ver=1.0\" async></script>";
        List<Technology> found = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body));
        assertThat(found).noneMatch(t -> t.name().equals("Bootstrap"));
    }

    @Test
    void bootstrapWithNoVersionSignal_stillDetectedButVersionNull() {
        String body = "<link rel=\"stylesheet\" href=\"/css/bootstrap.min.css\">";
        Technology bootstrap = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("Bootstrap"))
                .findFirst()
                .orElseThrow();
        assertThat(bootstrap.version()).isNull();
    }

    @Test
    void drupalMajorVersionCapturedFromGeneratorMeta() {
        String body = "<meta name=\"generator\" content=\"Drupal 10 (https://www.drupal.org)\" />";
        Technology drupal = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("Drupal"))
                .findFirst()
                .orElseThrow();
        assertThat(drupal.version()).isEqualTo("10");
    }

    @Test
    void joomlaDetectedButNeverCarriesAVersion() {
        String body = "<meta name=\"generator\" content=\"Joomla! - Open Source Content Management\" />";
        Technology joomla = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("Joomla"))
                .findFirst()
                .orElseThrow();
        assertThat(joomla.version()).isNull();
    }

    @Test
    void magentoDetectedFromCacheDebugHeader() {
        TechFetchResult result = new TechFetchResult(Map.of("x-magento-cache-debug", "HIT"), List.of(), "");
        assertThat(names(TechDecisionLogic.decide(result))).contains("Magento");
    }

    @Test
    void magentoDetectedFromBodySignal() {
        String body = "<script>var storage = window.localStorage.getItem('mage-cache-storage');</script>";
        assertThat(names(TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)))).contains("Magento");
    }

    @Test
    void wordPressPluginVersionDisclosedViaEnqueuedAssetQueryString() {
        String body = "<script src=\"/wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.7.2\"></script>";
        Technology plugin = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("WordPress Plugin: contact-form-7"))
                .findFirst()
                .orElseThrow();
        assertThat(plugin.version()).isEqualTo("5.7.2");
        assertThat(plugin.category()).isEqualTo(Technology.CMS);
    }

    @Test
    void wordPressThemeVersionDisclosedViaEnqueuedAssetQueryString() {
        String body = "<link rel=\"stylesheet\" href=\"/wp-content/themes/astra/style.css?ver=4.6.6\">";
        Technology theme = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)).stream()
                .filter(t -> t.name().equals("WordPress Theme: astra"))
                .findFirst()
                .orElseThrow();
        assertThat(theme.version()).isEqualTo("4.6.6");
    }

    @Test
    void multipleWordPressPlugins_eachReportedSeparately() {
        String body = "<script src=\"/wp-content/plugins/contact-form-7/scripts.js?ver=5.7.2\"></script>"
                + "<script src=\"/wp-content/plugins/woocommerce/frontend.js?ver=8.1.0\"></script>";
        List<String> found = names(TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)));
        assertThat(found).contains("WordPress Plugin: contact-form-7", "WordPress Plugin: woocommerce");
    }

    @Test
    void samePluginAssetSeenTwice_producesOneEntryNotTwo() {
        String body = "<script src=\"/wp-content/plugins/contact-form-7/a.js?ver=5.7.2\"></script>"
                + "<link rel=\"stylesheet\" href=\"/wp-content/plugins/contact-form-7/b.css?ver=5.7.2\">";
        List<Technology> found = TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body));
        assertThat(found.stream().filter(t -> t.name().equals("WordPress Plugin: contact-form-7")).count()).isEqualTo(1);
    }

    @Test
    void iisServerHeader_versionIsCaptured() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "Microsoft-IIS/10.0"), List.of(), "");
        Technology iis = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("IIS"))
                .findFirst()
                .orElseThrow();
        assertThat(iis.version()).isEqualTo("10.0");
        assertThat(iis.category()).isEqualTo(Technology.WEB_SERVER);
    }

    @Test
    void unrecognizedServerHeaderWithVersion_stillSurfacedGenerically() {
        // Real gap found live: GitHub.com's edge and other bespoke server products have no
        // dedicated signature above, and were being silently dropped rather than reported.
        TechFetchResult result = new TechFetchResult(Map.of("server", "openresty/1.21.4.1"), List.of(), "");
        Technology server = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("openresty"))
                .findFirst()
                .orElseThrow();
        assertThat(server.version()).isEqualTo("1.21.4.1");
        assertThat(server.category()).isEqualTo(Technology.WEB_SERVER);
    }

    @Test
    void unrecognizedServerHeaderWithoutVersion_reportedNameOnly() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "GitHub.com"), List.of(), "");
        Technology server = TechDecisionLogic.decide(result).stream()
                .filter(t -> t.name().equals("GitHub.com"))
                .findFirst()
                .orElseThrow();
        assertThat(server.version()).isNull();
        assertThat(server.category()).isEqualTo(Technology.WEB_SERVER);
    }

    @Test
    void cloudflareServerHeader_notAlsoReportedAsAGenericWebServer() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "cloudflare"), List.of(), "");
        List<Technology> found = TechDecisionLogic.decide(result);
        assertThat(found).hasSize(1);
        assertThat(found.get(0).name()).isEqualTo("Cloudflare");
        assertThat(found.get(0).category()).isEqualTo(Technology.CDN);
    }

    @Test
    void nginxServerHeader_notAlsoReportedGenerically() {
        TechFetchResult result = new TechFetchResult(Map.of("server", "nginx/1.25.3"), List.of(), "");
        List<Technology> found = TechDecisionLogic.decide(result);
        assertThat(found.stream().filter(t -> t.category().equals(Technology.WEB_SERVER)).count()).isEqualTo(1);
    }

    @Test
    void pluginAssetWithoutVersionQueryString_isNotReported() {
        // No ?ver= means no version signal to report at all - not worth a versionless
        // plugin entry when the slug alone (visible in every WordPress asset path
        // regardless) would be noisy without the version that makes it actionable.
        String body = "<script src=\"/wp-content/plugins/contact-form-7/scripts.js\"></script>";
        List<String> found = names(TechDecisionLogic.decide(new TechFetchResult(Map.of(), List.of(), body)));
        assertThat(found).doesNotContain("WordPress Plugin: contact-form-7");
    }
}
