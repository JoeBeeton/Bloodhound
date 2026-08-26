package org.freedonia.bloodhound.worker.modules.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class ThirdPartyOriginDecisionLogicTest {

    private static final String PAGE_URL = "https://www.example.com/";
    private static final String ROOT = "example.com";

    @Test
    void nullOrBlankHtml_noOrigins() {
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, null, ROOT, List.of())).isEmpty();
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, "", ROOT, List.of())).isEmpty();
    }

    @Test
    void thirdPartyScriptTag_detected() {
        String html = "<html><head><script src=\"https://www.googletagmanager.com/gtag/js?id=UA-1\"></script></head></html>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of()))
                .containsExactly("https://www.googletagmanager.com");
    }

    @Test
    void thirdPartyIframeTag_detected() {
        String html = "<iframe src=\"https://player.vimeo.com/video/12345\"></iframe>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of()))
                .containsExactly("https://player.vimeo.com");
    }

    @Test
    void ownRootHostname_notThirdParty() {
        String html = "<script src=\"https://example.com/main.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of())).isEmpty();
    }

    @Test
    void ownSubdomainViaApexSuffix_notThirdParty() {
        String html = "<script src=\"https://cdn.example.com/lib.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of())).isEmpty();
    }

    @Test
    void knownSubdomainList_notThirdPartyEvenIfNotApexSuffixMatch() {
        String html = "<script src=\"https://static.otherdomain.com/lib.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(
                        PAGE_URL, html, ROOT, List.of("static.otherdomain.com")))
                .isEmpty();
    }

    @Test
    void relativeScriptSrc_resolvedAndTreatedAsOwn() {
        String html = "<script src=\"/js/app.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of())).isEmpty();
    }

    @Test
    void similarLookingButDifferentDomain_notFooledByNaiveSuffixMatch() {
        // "notexample.com" ends with "example.com" as a raw string but is NOT a subdomain of it -
        // the "." + root check must require an actual dot boundary, not just any suffix match.
        String html = "<script src=\"https://notexample.com/evil.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of()))
                .containsExactly("https://notexample.com");
    }

    @Test
    void dataUriScriptSrc_ignored() {
        String html = "<script src=\"data:text/javascript;base64,YWxlcnQoMSk=\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of())).isEmpty();
    }

    @Test
    void multipleThirdPartyOrigins_deduplicatedAndSorted() {
        String html = "<script src=\"https://www.googletagmanager.com/a.js\"></script>"
                + "<script src=\"https://www.googletagmanager.com/b.js\"></script>"
                + "<script src=\"https://cdn.jsdelivr.net/lib.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of()))
                .containsExactly("https://cdn.jsdelivr.net", "https://www.googletagmanager.com");
    }

    @Test
    void mixedCaseHostname_normalizedToLowercase() {
        String html = "<script src=\"https://WWW.GoogleTagManager.com/gtag.js\"></script>";
        assertThat(ThirdPartyOriginDecisionLogic.extractThirdPartyOrigins(PAGE_URL, html, ROOT, List.of()))
                .containsExactly("https://www.googletagmanager.com");
    }
}
