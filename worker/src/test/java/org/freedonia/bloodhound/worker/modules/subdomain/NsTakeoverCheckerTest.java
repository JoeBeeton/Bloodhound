package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Only the network-free branches - see DanglingCnameCheckerTest's javadoc
 * for why this is the safe subset to unit test: {@link
 * NsTakeoverDecisionLogic#matchProvider} is a pure local check done before
 * any DNS query, and a nameserver list matching no known provider never
 * reaches {@code respondsAuthoritatively} (a real network call) at all.
 */
class NsTakeoverCheckerTest {

    private final NsTakeoverChecker checker = new NsTakeoverChecker();

    @Test
    void emptyBatch_returnsEmptyMap_noNetworkCall() {
        assertThat(checker.checkAll(Map.of())).isEmpty();
    }

    @Test
    void nameserversMatchingNoKnownProvider_shortCircuitsWithoutQuery() {
        Map<String, NsTakeoverChecker.Result> results = checker.checkAll(
                Map.of("host.example.com", List.of("ns1.not-a-known-dns-provider.example.net")));

        assertThat(results).containsKey("host.example.com");
        NsTakeoverChecker.Result result = results.get("host.example.com");
        assertThat(result.confirmedTakeover()).isFalse();
        assertThat(result.provider()).isNull();
        assertThat(result.nameserver()).isNull();
    }

    @Test
    void emptyNameserverList_treatedAsNoMatch() {
        Map<String, NsTakeoverChecker.Result> results = checker.checkAll(Map.of("host.example.com", List.of()));

        assertThat(results.get("host.example.com").confirmedTakeover()).isFalse();
    }
}
