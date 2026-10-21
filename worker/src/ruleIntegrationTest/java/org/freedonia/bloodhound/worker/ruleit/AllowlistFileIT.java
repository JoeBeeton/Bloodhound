package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Runs without the network namespace. The file is what the Gradle task and the runner export. */
class AllowlistFileIT {

    @Test
    void allowlistListsEveryScannedFixtureHost() throws Exception {
        List<String> hosts = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                AllowlistFileIT.class.getResourceAsStream("/ssrf-allowlist.txt"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String host = line;
                int comment = host.indexOf('#');
                if (comment >= 0) {
                    host = host.substring(0, comment);
                }
                host = host.trim();
                if (!host.isEmpty()) {
                    hosts.add(host);
                }
            }
        }
        assertThat(hosts).containsExactlyInAnyOrderElementsOf(FixtureHosts.SCANNED);
    }
}
