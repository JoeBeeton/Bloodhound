package org.freedonia.bloodhound.worker.modules.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.junit.jupiter.api.Test;

class HostFanOutTest {

    private static RawFinding fakeFinding(String hostname) {
        return new RawFinding("FAKE_RULE", Severity.INFO, Category.HEADERS, "title", "description", hostname, Map.of());
    }

    @Test
    void allHostsReachable_returnsFindingsFromEveryHost() throws Exception {
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com",
                List.of("a.example.com", "b.example.com"),
                40,
                4,
                5,
                hostname -> List.of(fakeFinding(hostname)));

        assertThat(result.hostsCovered()).containsExactlyInAnyOrder("root.example.com", "a.example.com", "b.example.com");
        assertThat(result.findings()).extracting(RawFinding::affectedAsset)
                .containsExactlyInAnyOrder("root.example.com", "a.example.com", "b.example.com");
        assertThat(result.hostsAttempted()).isEqualTo(3);
    }

    @Test
    void rootUnreachableButSubdomainsReachable_succeedsWithPartialCoverage() throws Exception {
        // The real-world case this whole change exists for: an apex with no
        // A/AAAA record at all, while its subdomains resolve fine.
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com",
                List.of("a.example.com", "b.example.com"),
                40,
                4,
                5,
                hostname -> {
                    if (hostname.equals("root.example.com")) {
                        throw new RuntimeException("could not resolve host");
                    }
                    return List.of(fakeFinding(hostname));
                });

        assertThat(result.hostsCovered()).containsExactlyInAnyOrder("a.example.com", "b.example.com");
        assertThat(result.findings()).extracting(RawFinding::affectedAsset)
                .containsExactlyInAnyOrder("a.example.com", "b.example.com");
    }

    @Test
    void someSubdomainsUnreachable_skipsThemAndUsesTheRest() throws Exception {
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com",
                List.of("a.example.com", "b.example.com", "c.example.com"),
                40,
                4,
                5,
                hostname -> {
                    if (hostname.equals("b.example.com")) {
                        throw new RuntimeException("connection refused");
                    }
                    return List.of(fakeFinding(hostname));
                });

        assertThat(result.hostsCovered())
                .containsExactlyInAnyOrder("root.example.com", "a.example.com", "c.example.com")
                .doesNotContain("b.example.com");
    }

    @Test
    void everyHostUnreachable_throws() {
        assertThatThrownBy(() -> HostFanOut.run(
                        "root.example.com",
                        List.of("a.example.com", "b.example.com"),
                        40,
                        4,
                        5,
                        hostname -> {
                            throw new RuntimeException("could not resolve host");
                        }))
                .isInstanceOf(ScanModuleException.class)
                .hasMessageContaining("root.example.com")
                .hasMessageContaining("2");
    }

    @Test
    void noSubdomains_stillScansRootAlone() throws Exception {
        HostFanOut.Result result =
                HostFanOut.run("root.example.com", List.of(), 40, 4, 5, hostname -> List.of(fakeFinding(hostname)));
        assertThat(result.hostsCovered()).containsExactly("root.example.com");
    }

    @Test
    void subdomainCountExceedsCap_onlyFirstCapAreAttempted() throws Exception {
        List<String> manySubdomains =
                List.of("a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com");
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com", manySubdomains, 2, 4, 5, hostname -> List.of(fakeFinding(hostname)));

        // root + first 2 subdomains = 3 total, regardless of 5 being known
        assertThat(result.hostsAttempted()).isEqualTo(3);
    }

    @Test
    void perHostTimeout_treatsHangingHostAsFailedNotWholeRun() throws Exception {
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com",
                List.of("slow.example.com"),
                40,
                4,
                1, // 1 second timeout
                hostname -> {
                    if (hostname.equals("slow.example.com")) {
                        Thread.sleep(5000);
                    }
                    return List.of(fakeFinding(hostname));
                });

        assertThat(result.hostsCovered()).containsExactly("root.example.com");
    }

    @Test
    void concurrentExecution_isThreadSafeAcrossHosts() throws Exception {
        Set<String> observedHosts = ConcurrentHashMap.newKeySet();
        List<String> subdomains = List.of("a.example.com", "b.example.com", "c.example.com", "d.example.com");
        HostFanOut.Result result = HostFanOut.run(
                "root.example.com",
                subdomains,
                40,
                4,
                5,
                hostname -> {
                    observedHosts.add(hostname);
                    return List.of(fakeFinding(hostname));
                });
        assertThat(observedHosts).hasSize(5);
        assertThat(result.hostsCovered()).hasSize(5);
    }

    // --- runPerHost: same semantics as run(), but one arbitrary value per
    // host instead of a flattened findings list (used by FingerprintModule,
    // which needs each host's own technology/hosting-provider record kept
    // separate rather than merged together). ---

    @Test
    void runPerHost_allReachable_returnsOneValuePerHost() throws Exception {
        HostFanOut.ValueResult<String> result = HostFanOut.runPerHost(
                "root.example.com",
                List.of("a.example.com", "b.example.com"),
                40,
                4,
                5,
                hostname -> "fingerprint-of-" + hostname);

        assertThat(result.hostsCovered()).containsExactlyInAnyOrder("root.example.com", "a.example.com", "b.example.com");
        assertThat(result.perHostResults())
                .containsExactlyInAnyOrder(
                        "fingerprint-of-root.example.com",
                        "fingerprint-of-a.example.com",
                        "fingerprint-of-b.example.com");
    }

    @Test
    void runPerHost_rootUnreachableButSubdomainsReachable_succeedsWithPartialCoverage() throws Exception {
        // The exact bug this method was added to fix: TECH_FINGERPRINT used
        // to fail its whole job whenever the apex had no A/AAAA record, even
        // when several of its subdomains resolved fine and could have been
        // fingerprinted successfully.
        HostFanOut.ValueResult<String> result = HostFanOut.runPerHost(
                "root.example.com",
                List.of("a.example.com", "b.example.com"),
                40,
                4,
                5,
                hostname -> {
                    if (hostname.equals("root.example.com")) {
                        throw new RuntimeException("could not resolve host");
                    }
                    return "fingerprint-of-" + hostname;
                });

        assertThat(result.hostsCovered()).containsExactlyInAnyOrder("a.example.com", "b.example.com");
        assertThat(result.perHostResults())
                .containsExactlyInAnyOrder("fingerprint-of-a.example.com", "fingerprint-of-b.example.com");
    }

    @Test
    void runPerHost_everyHostUnreachable_throws() {
        assertThatThrownBy(() -> HostFanOut.runPerHost(
                        "root.example.com",
                        List.of("a.example.com", "b.example.com"),
                        40,
                        4,
                        5,
                        hostname -> {
                            throw new RuntimeException("could not resolve host");
                        }))
                .isInstanceOf(ScanModuleException.class)
                .hasMessageContaining("root.example.com")
                .hasMessageContaining("2");
    }
}
