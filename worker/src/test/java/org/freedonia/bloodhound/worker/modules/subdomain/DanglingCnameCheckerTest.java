package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Only the network-free branches: an empty batch, and any CNAME that
 * doesn't match a known takeover-prone provider - {@link
 * DanglingCnameDecisionLogic#matchProvider} is a pure local check done
 * BEFORE any HTTP call, so these paths never touch the network and are safe
 * to assert on directly. The confirmation-fetch path (a real CNAME match)
 * genuinely needs a live HTTP call and is out of scope for a unit test here.
 */
class DanglingCnameCheckerTest {

    private final DanglingCnameChecker checker = new DanglingCnameChecker();

    @Test
    void emptyBatch_returnsEmptyMap_noNetworkCall() {
        assertThat(checker.checkAll(Map.of())).isEmpty();
    }

    @Test
    void cnameMatchingNoKnownProvider_shortCircuitsWithoutFetch() {
        Map<String, DanglingCnameChecker.Result> results =
                checker.checkAll(Map.of("host.example.com", "not-a-known-provider.example.net"));

        assertThat(results).containsKey("host.example.com");
        DanglingCnameChecker.Result result = results.get("host.example.com");
        assertThat(result.confirmedDangling()).isFalse();
        assertThat(result.matchedService()).isNull();
        assertThat(result.cnameTarget()).isEqualTo("not-a-known-provider.example.net");
    }

    @Test
    void multipleNonMatchingHosts_allShortCircuit() {
        Map<String, DanglingCnameChecker.Result> results = checker.checkAll(Map.of(
                "a.example.com", "irrelevant-one.example.net",
                "b.example.com", "irrelevant-two.example.net"));

        assertThat(results).hasSize(2);
        assertThat(results.values()).allSatisfy(r -> assertThat(r.confirmedDangling()).isFalse());
    }
}
