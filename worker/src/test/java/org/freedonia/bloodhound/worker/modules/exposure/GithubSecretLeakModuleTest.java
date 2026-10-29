package org.freedonia.bloodhound.worker.modules.exposure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.junit.jupiter.api.Test;

class GithubSecretLeakModuleTest {

    private final GithubSecretLeakFetcher fetcher = mock(GithubSecretLeakFetcher.class);
    private final GithubSecretLeakModule module = new GithubSecretLeakModule(fetcher);
    private final UUID targetId = UUID.randomUUID();
    private final ScanContext context = new ScanContext(targetId, "example.com", List.of(), Map.of());

    @Test
    void noTokenConfigured_disabledAndNoFindings() throws Exception {
        when(fetcher.fetch(targetId, "example.com"))
                .thenReturn(new GithubSecretLeakFetcher.FetchResult(false, List.of()));

        ModuleResult result = module.execute(context);

        assertThat(result.findings()).isEmpty();
        assertThat(result.rawMetadata()).containsEntry("enabled", false);
    }

    @Test
    void enabledWithNoSecretShapedCandidates_emptyFindings_butEnabledTrue() throws Exception {
        GithubSecretLeakFetcher.CandidateFile clean =
                new GithubSecretLeakFetcher.CandidateFile("acme/webapp", "src/index.js", "https://github.com/acme/webapp/blob/main/src/index.js", "function add(a,b){return a+b;}");
        when(fetcher.fetch(targetId, "example.com"))
                .thenReturn(new GithubSecretLeakFetcher.FetchResult(true, List.of(clean)));

        ModuleResult result = module.execute(context);

        assertThat(result.findings()).isEmpty();
        assertThat(result.rawMetadata()).containsEntry("enabled", true).containsEntry("candidatesChecked", 1);
    }

    @Test
    void enabledWithASecretShapedCandidate_emitsFinding() throws Exception {
        String fakeAwsKey = "AKIA" + "ABCDEFGHIJKLMNOP";
        GithubSecretLeakFetcher.CandidateFile leaky = new GithubSecretLeakFetcher.CandidateFile(
                "acme/webapp", "config/secrets.js", "https://github.com/acme/webapp/blob/main/config/secrets.js",
                "const key = '" + fakeAwsKey + "';");
        when(fetcher.fetch(targetId, "example.com"))
                .thenReturn(new GithubSecretLeakFetcher.FetchResult(true, List.of(leaky)));

        ModuleResult result = module.execute(context);

        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().get(0).ruleId()).isEqualTo("EXPOSURE_SECRET_IN_PUBLIC_REPO");
        assertThat(result.rawMetadata()).containsEntry("findingCount", 1);
    }
}
