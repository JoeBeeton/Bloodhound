package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Only the network-free branches - see DanglingCnameCheckerTest's javadoc
 * for why this is the safe subset to unit test: {@link
 * CloudBucketDecisionLogic#matchProvider} is a pure local check done before
 * any HTTP call.
 */
class CloudBucketCheckerTest {

    private final CloudBucketChecker checker = new CloudBucketChecker();

    @Test
    void emptyBatch_returnsEmptyMap_noNetworkCall() {
        assertThat(checker.checkAll(Map.of())).isEmpty();
    }

    @Test
    void hostnameAndCnameMatchingNoKnownProvider_shortCircuitsWithoutFetch_omittedFromResults() {
        Map<String, CloudBucketChecker.Result> results =
                checker.checkAll(Map.of("host.example.com", "not-a-bucket-provider.example.net"));

        // Unlike DanglingCnameChecker, a non-match is omitted from the results map entirely
        // (checkOne returns Optional.empty(), not a negative Result) - see CloudBucketChecker#checkOne.
        assertThat(results).isEmpty();
    }

    @Test
    void multipleNonMatchingHosts_allOmitted() {
        Map<String, CloudBucketChecker.Result> results = checker.checkAll(Map.of(
                "a.example.com", "irrelevant-one.example.net",
                "b.example.com", "irrelevant-two.example.net"));

        assertThat(results).isEmpty();
    }
}
