package org.freedonia.bloodhound.worker.modules.exposure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class GithubSecretLeakDecisionLogicTest {

    @Test
    void disabledResult_producesNoFindings_regardlessOfCandidates() {
        // Shouldn't happen in practice (the fetcher returns an empty candidate list when
        // disabled), but decide() itself must not interpret candidates it's told to ignore.
        GithubSecretLeakFetcher.CandidateFile file =
                new GithubSecretLeakFetcher.CandidateFile("acme/repo", "a.js", "https://github.com/acme/repo/blob/main/a.js", "whatever");
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(false, List.of(file));

        assertThat(GithubSecretLeakDecisionLogic.decide("example.com", result)).isEmpty();
    }

    @Test
    void enabledNoCandidates_noFindings() {
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(true, List.of());

        assertThat(GithubSecretLeakDecisionLogic.decide("example.com", result)).isEmpty();
    }

    @Test
    void candidateWithSecretShapedContent_flaggedCriticalWithRepoPathAndUrlEvidence() {
        // Split across two literals, not a real key - see this session's own lesson on not
        // tripping GitHub's real secret scanner with a contiguous fake key in test source.
        String fakeAwsKey = "AKIA" + "ABCDEFGHIJKLMNOP";
        String body = "const AWS_KEY = '" + fakeAwsKey + "';";
        GithubSecretLeakFetcher.CandidateFile file = new GithubSecretLeakFetcher.CandidateFile(
                "acme/webapp", "config/secrets.js", "https://github.com/acme/webapp/blob/main/config/secrets.js", body);
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(true, List.of(file));

        List<RawFinding> findings = GithubSecretLeakDecisionLogic.decide("example.com", result);

        assertThat(findings).hasSize(1);
        RawFinding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("EXPOSURE_SECRET_IN_PUBLIC_REPO");
        assertThat(finding.severity().name()).isEqualTo("CRITICAL");
        assertThat(finding.affectedAsset()).isEqualTo("example.com (acme/webapp/config/secrets.js)");
        assertThat(finding.evidence())
                .containsEntry("repo", "acme/webapp")
                .containsEntry("path", "config/secrets.js")
                .containsEntry("url", "https://github.com/acme/webapp/blob/main/config/secrets.js");
        @SuppressWarnings("unchecked")
        List<String> patternsFound = (List<String>) finding.evidence().get("patternsFound");
        assertThat(patternsFound).contains("AWS Access Key ID");
    }

    @Test
    void candidateWithCleanContent_noFindingEmitted() {
        GithubSecretLeakFetcher.CandidateFile file = new GithubSecretLeakFetcher.CandidateFile(
                "acme/webapp", "src/index.js", "https://github.com/acme/webapp/blob/main/src/index.js",
                "function add(a, b) { return a + b; }");
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(true, List.of(file));

        assertThat(GithubSecretLeakDecisionLogic.decide("example.com", result)).isEmpty();
    }

    @Test
    void multipleCandidates_onlyTheSecretShapedOneProducesAFinding() {
        String fakeAwsKey = "AKIA" + "ZZZZZZZZZZZZZZZZ";
        GithubSecretLeakFetcher.CandidateFile clean = new GithubSecretLeakFetcher.CandidateFile(
                "acme/webapp", "src/index.js", "https://github.com/acme/webapp/blob/main/src/index.js", "no secrets here");
        GithubSecretLeakFetcher.CandidateFile leaky = new GithubSecretLeakFetcher.CandidateFile(
                "acme/webapp", "config/secrets.js", "https://github.com/acme/webapp/blob/main/config/secrets.js",
                "const key = '" + fakeAwsKey + "';");
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(true, List.of(clean, leaky));

        List<RawFinding> findings = GithubSecretLeakDecisionLogic.decide("example.com", result);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).evidence()).containsEntry("path", "config/secrets.js");
    }

    @Test
    void missingRepoName_fallsBackRatherThanThrowing() {
        String fakeAwsKey = "AKIA" + "QQQQQQQQQQQQQQQQ";
        GithubSecretLeakFetcher.CandidateFile file = new GithubSecretLeakFetcher.CandidateFile(
                null, "secrets.js", null, "const key = '" + fakeAwsKey + "';");
        GithubSecretLeakFetcher.FetchResult result = new GithubSecretLeakFetcher.FetchResult(true, List.of(file));

        List<RawFinding> findings = GithubSecretLeakDecisionLogic.decide("example.com", result);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).evidence()).containsEntry("repo", "unknown repository").containsEntry("url", "");
    }
}
