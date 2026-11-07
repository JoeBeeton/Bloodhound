package org.freedonia.bloodhound.worker.modules.http;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.Test;

class OpenRedirectLocationTest {

    private static final URI APEX = URI.create("https://example.com/?redirect=https%3A%2F%2Fbh-open-redirect-probe.invalid%2F");

    @Test
    void resolve_relativeLocationUsesTheBase() {
        assertThat(OpenRedirectLocation.resolve(APEX, "/se/?a=1")).hasToString("https://example.com/se/?a=1");
    }

    @Test
    void resolve_illegalCharactersAreEscapedRatherThanRejected() {
        assertThat(OpenRedirectLocation.resolve(APEX, "/a b|c")).hasToString("https://example.com/a%20b%7Cc");
    }

    @Test
    void resolve_nullOrBlank_null() {
        assertThat(OpenRedirectLocation.resolve(APEX, null)).isNull();
        assertThat(OpenRedirectLocation.resolve(APEX, "   ")).isNull();
    }

    @Test
    void hostOf_underscoreHostFallsBackToAuthority() {
        assertThat(OpenRedirectLocation.hostOf(URI.create("https://user@my_host.Example.com.:8443/x")))
                .isEqualTo("my_host.example.com");
    }

    @Test
    void followable_apexToWwwKeepingTheProbeValue() {
        URI next = OpenRedirectLocation.resolve(
                APEX, "https://www.example.com/?redirect=https%3A%2F%2Fbh-open-redirect-probe.invalid%2F");
        assertThat(OpenRedirectLocation.followable(next, "example.com", "example.com")).isTrue();
    }

    @Test
    void followable_siblingSubdomainUnderTheTargetRoot() {
        URI next = URI.create("https://www.example.com/careers/?redirect=https%3A%2F%2Fbh-open-redirect-probe.invalid%2F");
        assertThat(OpenRedirectLocation.followable(next, "example.com", "careers.example.com")).isTrue();
    }

    @Test
    void followable_sameSiteButProbeValueDropped_notFollowed() {
        assertThat(OpenRedirectLocation.followable(URI.create("https://www.example.com/"), "example.com", "example.com"))
                .isFalse();
    }

    @Test
    void followable_thirdPartyHost_notFollowed() {
        URI sso = URI.create("https://login.example-sso.com/authorize?redirect_uri=bh-open-redirect-probe.invalid");
        assertThat(OpenRedirectLocation.followable(sso, "example.com", "example.com")).isFalse();
    }

    @Test
    void followable_lookalikeSuffixIsNotSameSite() {
        URI next = URI.create("https://notexample.com/?redirect=bh-open-redirect-probe.invalid");
        assertThat(OpenRedirectLocation.followable(next, "example.com", "example.com")).isFalse();
    }

    @Test
    void followable_nonHttpScheme_notFollowed() {
        URI next = URI.create("ftp://www.example.com/?redirect=bh-open-redirect-probe.invalid");
        assertThat(OpenRedirectLocation.followable(next, "example.com", "example.com")).isFalse();
    }

    @Test
    void followable_nullRootFallsBackToTheProbedHost() {
        URI next = URI.create("https://www.example.com/?redirect=bh-open-redirect-probe.invalid");
        assertThat(OpenRedirectLocation.followable(next, null, "example.com")).isTrue();
        assertThat(OpenRedirectLocation.followable(next, null, "app.example.com")).isFalse();
    }
}
