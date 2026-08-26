package org.freedonia.bloodhound.worker.modules.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.junit.jupiter.api.Test;

class PayloadSubdomainsTest {

    private static ScanContext context(Map<String, Object> payload) {
        return new ScanContext(UUID.randomUUID(), "root.example.com", List.of(), payload);
    }

    @Test
    void singleHost_readsHostKeyFromPayload() {
        assertThat(PayloadSubdomains.singleHost(context(Map.of("host", "sub.example.com"))))
                .isEqualTo("sub.example.com");
    }

    @Test
    void singleHost_fallsBackToContextHostnameWhenPayloadHasNoHostKey() {
        assertThat(PayloadSubdomains.singleHost(context(Map.of()))).isEqualTo("root.example.com");
    }

    @Test
    void singleHost_fallsBackToContextHostnameWhenPayloadIsNull() {
        assertThat(PayloadSubdomains.singleHost(context(null))).isEqualTo("root.example.com");
    }

    @Test
    void singleHost_ignoresLegacyMultiHostSubdomainsKey() {
        // A job predating per-host dispatch would carry {"subdomains": [...]}, not {"host": ...} -
        // singleHost must not mistake that list for anything, and fall back to the root hostname.
        assertThat(PayloadSubdomains.singleHost(context(Map.of("subdomains", List.of("a.example.com", "b.example.com")))))
                .isEqualTo("root.example.com");
    }

    @Test
    void from_stillReadsTheMultiHostSubdomainsKey_unaffectedByHostAddition() {
        assertThat(PayloadSubdomains.from(context(Map.of("subdomains", List.of("a.example.com", "b.example.com")))))
                .containsExactly("a.example.com", "b.example.com");
    }
}
