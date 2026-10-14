package org.freedonia.bloodhound.worker.modules.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HstsPreloadClientTest {

    private final HstsPreloadClient client = new HstsPreloadClient();

    /** The real, live-captured response shape for a domain actually on the list. */
    @Test
    void parseStatus_preloadedDomain_extractsPreloaded() {
        String json = "{\"name\":\"github.com\",\"status\":\"preloaded\",\"bulk\":true,\"preloadedDomain\":\"github.com\"}";
        assertThat(client.parseStatus(json)).isEqualTo("preloaded");
    }

    /** The real, live-captured response shape for a domain never submitted. */
    @Test
    void parseStatus_neverSubmittedDomain_extractsUnknown() {
        String json = "{\"name\":\"example.com\",\"status\":\"unknown\",\"bulk\":false,\"preloadedDomain\":\"\"}";
        assertThat(client.parseStatus(json)).isEqualTo("unknown");
    }

    @Test
    void parseStatus_nullInput_returnsNull() {
        assertThat(client.parseStatus(null)).isNull();
    }

    @Test
    void parseStatus_malformedJson_returnsNullRatherThanThrowing() {
        assertThat(client.parseStatus("not json")).isNull();
    }

    @Test
    void parseStatus_missingStatusField_returnsNull() {
        assertThat(client.parseStatus("{\"name\":\"example.com\"}")).isNull();
    }
}
