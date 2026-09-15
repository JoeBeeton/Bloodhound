package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Pure parser tests - zero process execution. Fixtures shaped like katana v1.7.0's real jsonl output. */
class KatanaCliSourceTest {

    private static final String ROOT = "example.com";

    @Test
    void keepsJsTaggedEndpointWithinScope() {
        String stdout = jsRecord("https://example.com/app.js", "https://api.example.com/v2/login");
        assertThat(KatanaCliSource.parse(stdout, ROOT)).containsExactly("api.example.com");
    }

    @Test
    void ignoresNonJsTaggedEndpoints() {
        // "a" is katana's tag for a plain HTML link, not a js-content-parsed endpoint - this
        // source only cares about the latter (see class doc for why).
        String stdout = "{\"request\":{\"tag\":\"a\",\"source\":\"https://example.com/\","
                + "\"endpoint\":\"https://internal.example.com/\"}}\n";
        assertThat(KatanaCliSource.parse(stdout, ROOT)).isEmpty();
    }

    @Test
    void ignoresOutOfScopeHosts() {
        // Confirmed live: katana reports third-party hosts it fetches (fonts.googleapis.com
        // etc.) as "js" records too, despite -fs rdn - this source must filter them itself.
        String stdout = jsRecord("https://example.com/app.js", "https://fonts.googleapis.com/css2");
        assertThat(KatanaCliSource.parse(stdout, ROOT)).isEmpty();
    }

    @Test
    void keepsBareRootDomainItself() {
        String stdout = jsRecord("https://example.com/app.js", "https://example.com/api/status");
        assertThat(KatanaCliSource.parse(stdout, ROOT)).containsExactly("example.com");
    }

    @Test
    void dedupesRepeatedHostnames() {
        String stdout = jsRecord("https://example.com/a.js", "https://api.example.com/one")
                + jsRecord("https://example.com/b.js", "https://api.example.com/two");
        assertThat(KatanaCliSource.parse(stdout, ROOT)).containsExactly("api.example.com");
    }

    @Test
    void toleratesMalformedOrTruncatedLines() {
        // A line cut off mid-JSON by the shared watchdog's forced kill, plus a js-tagged
        // "endpoint" that isn't a real absolute URI (katana's regex js-parsing occasionally
        // matches non-URL-shaped strings) - neither should fail the whole parse.
        String stdout = "{\"request\":{\"tag\":\"js\",\"source\":\"https://example.com/a.js\","
                + "\"endpoint\":\"not a url\"}}\n"
                + "{\"request\":{\"tag\":\"js\",\"sour\n"
                + jsRecord("https://example.com/b.js", "https://api.example.com/ok");
        assertThat(KatanaCliSource.parse(stdout, ROOT)).containsExactly("api.example.com");
    }

    @Test
    void emptyOrNullOutputYieldsEmptyList() {
        assertThat(KatanaCliSource.parse("", ROOT)).isEmpty();
        assertThat(KatanaCliSource.parse("   \n  \n", ROOT)).isEmpty();
        assertThat(KatanaCliSource.parse(null, ROOT)).isEmpty();
    }

    @Test
    void sourceNameIsKatana() {
        assertThat(new KatanaCliSource().sourceName()).isEqualTo("KATANA");
    }

    private static String jsRecord(String source, String endpoint) {
        return "{\"request\":{\"tag\":\"js\",\"source\":\"" + source + "\",\"endpoint\":\"" + endpoint + "\"}}\n";
    }
}
