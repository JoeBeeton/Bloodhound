package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TyposquatPageProbeTest {

    @Test
    void forSaleLander_parking() {
        var page = TyposquatPageProbe.classify(
                "exampl.com", "<html><title>exampl.com</title><h1>This domain may be for sale!</h1></html>");
        assertThat(page.parkingPage()).isTrue();
        assertThat(page.challengePage()).isFalse();
        assertThat(page.landingHost()).isEqualTo("exampl.com");
    }

    @Test
    void redirectedToAMarketplace_parking() {
        var page = TyposquatPageProbe.classify("domains.atom.com", "<html><body>Premium name</body></html>");
        assertThat(page.parkingPage()).isTrue();
    }

    @Test
    void ordinaryBusinessSite_notParkingOrChallenge() {
        var page = TyposquatPageProbe.classify(
                "exampl.com", "<html><title>Exampl Furniture</title><p>Handmade tables since 1998</p></html>");
        assertThat(page.parkingPage()).isFalse();
        assertThat(page.challengePage()).isFalse();
    }

    @Test
    void botChallenge_detected() {
        var page = TyposquatPageProbe.classify(
                "www.example.com", "<html><title>Just a quick security check | Example</title></html>");
        assertThat(page.challengePage()).isTrue();
    }

    @Test
    void metaRefreshStub_landingHostIsTheRefreshTarget() {
        var page = TyposquatPageProbe.classify(
                "exampl.com",
                "<html><head><meta http-equiv=\"refresh\" content=\"0;url=https://www.example.com/\"></head></html>");
        assertThat(page.landingHost()).isEqualTo("www.example.com");
    }

    /**
     * A phishing page commonly forwards victims to the real brand after capturing credentials -
     * that script must not make the page count as "redirects to the brand".
     */
    @Test
    void jsRedirectInsideAFullPage_ignored() {
        String body = "<html><form action=\"/collect\"><input name=\"password\"></form>"
                + "<script>function done(){ window.location.href = \"https://www.example.com/login\"; }</script>"
                + "x".repeat(5_000) + "</html>";
        assertThat(TyposquatPageProbe.classify("exampl.com", body).landingHost()).isEqualTo("exampl.com");
    }

    @Test
    void jsRedirectStub_followed() {
        var page = TyposquatPageProbe.classify(
                "exampl.com", "<script>window.location.href = \"https://www.example.com/\";</script>");
        assertThat(page.landingHost()).isEqualTo("www.example.com");
    }
}
