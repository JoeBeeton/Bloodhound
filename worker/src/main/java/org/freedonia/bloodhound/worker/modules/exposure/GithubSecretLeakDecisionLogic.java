package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of an already-fetched {@link GithubSecretLeakFetcher.FetchResult} into
 * findings - no network calls, fully unit-testable. Reuses {@link SecretPatternScanner} - the
 * same matcher already applied to .env/.git/config/.aws/credentials/JS-bundle findings in
 * {@link ExposedPathDecisionLogic} - against each candidate public-repo file's body. A separate
 * rule_id from EXPOSURE_LIVE_SECRET_DETECTED (not a reuse via a fileLabel, the way those other
 * sources share it): the evidence shape here is genuinely different - a repo name, file path,
 * and GitHub URL, not an on-host fileLabel.
 */
public final class GithubSecretLeakDecisionLogic {

    private GithubSecretLeakDecisionLogic() {}

    public static List<RawFinding> decide(String rootDomain, GithubSecretLeakFetcher.FetchResult result) {
        if (!result.enabled()) {
            return List.of();
        }
        List<RawFinding> findings = new ArrayList<>();
        for (GithubSecretLeakFetcher.CandidateFile file : result.candidateFiles()) {
            List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(file.body());
            if (matches.isEmpty()) {
                continue;
            }
            String repo = file.repoFullName() == null ? "unknown repository" : file.repoFullName();
            List<String> patternNames = matches.stream().map(SecretPatternScanner.Match::patternName).toList();
            List<String> previews = matches.stream().map(SecretPatternScanner.Match::redactedPreview).toList();
            findings.add(new RawFinding(
                    "EXPOSURE_SECRET_IN_PUBLIC_REPO",
                    Severity.CRITICAL,
                    Category.EXPOSURE,
                    "Live-looking secret found in a public code repository",
                    "A public GitHub repository mentioning this domain contains a string matching a known "
                            + "live-credential format.",
                    rootDomain + " (" + repo + "/" + file.path() + ")",
                    Map.of(
                            "repo", repo,
                            "path", file.path(),
                            "url", file.htmlUrl() == null ? "" : file.htmlUrl(),
                            "patternsFound", patternNames,
                            "matchCount", matches.size(),
                            "previews", previews)));
        }
        return findings;
    }
}
