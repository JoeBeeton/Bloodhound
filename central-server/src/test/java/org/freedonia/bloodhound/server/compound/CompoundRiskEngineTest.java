package org.freedonia.bloodhound.server.compound;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.Test;

class CompoundRiskEngineTest {

    private static Finding finding(String ruleId, String severity, String category, String asset) {
        UUID run = UUID.randomUUID();
        return new Finding(
                UUID.randomUUID(),
                "bh-test-1",
                run,
                UUID.randomUUID(),
                "SOME_MODULE",
                ruleId,
                severity,
                category,
                "title",
                "description",
                "{}",
                asset,
                run,
                "OPEN",
                null,
                Instant.now(),
                Instant.now());
    }

    @Test
    void credentialToDataPivot_firesWhenBothGroupsPresentOnSameAsset() {
        List<Finding> findings = List.of(
                finding("EXPOSURE_ENV_FILE", "CRITICAL", "EXPOSURE", "api.example.com"),
                finding("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "HIGH", "NETWORK", "api.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches).hasSize(1);
        CompoundMatch match = matches.get(0);
        assertThat(match.pattern().ruleId()).isEqualTo("COMPOUND_CREDENTIAL_TO_DATA_PIVOT");
        assertThat(match.affectedAsset()).isEqualTo("api.example.com");
        assertThat(match.contributingFindings()).hasSize(2);
    }

    @Test
    void credentialToDataPivot_doesNotFireWithOnlyOneGroupPresent() {
        List<Finding> findings = List.of(finding("EXPOSURE_ENV_FILE", "CRITICAL", "EXPOSURE", "api.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }

    @Test
    void credentialToDataPivot_doesNotFireAcrossDifferentAssets() {
        List<Finding> findings = List.of(
                finding("EXPOSURE_ENV_FILE", "CRITICAL", "EXPOSURE", "api.example.com"),
                finding("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "HIGH", "NETWORK", "db.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }

    @Test
    void containerEscapeAmplification_firesWithDockerApiPlusAnotherCriticalFinding() {
        List<Finding> findings = List.of(
                finding("EXPOSURE_DOCKER_API", "CRITICAL", "EXPOSURE", "host.example.com"),
                finding("TLS_CERT_EXPIRED", "CRITICAL", "TLS", "host.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches).anySatisfy(
                m -> assertThat(m.pattern().ruleId()).isEqualTo("COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION"));
    }

    @Test
    void containerEscapeAmplification_singleDockerApiFindingCannotSatisfyBothGroupsByItself() {
        // EXPOSURE_DOCKER_API is itself Critical severity in the real catalog - proves group B's
        // exclusion of the trigger rule_id is load-bearing, not just a documentation comment.
        List<Finding> findings = List.of(finding("EXPOSURE_DOCKER_API", "CRITICAL", "EXPOSURE", "host.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }

    @Test
    void activelyExploitedExposure_doesNotSelfTrigger_kevFindingAloneNotEnoughDespiteSameCategory() {
        // TECH_KNOWN_EXPLOITED_VULNERABILITY's own category is EXPOSURE, same as group B's
        // predicate - proves the explicit ruleId exclusion in group B is load-bearing.
        List<Finding> findings =
                List.of(finding("TECH_KNOWN_EXPLOITED_VULNERABILITY", "CRITICAL", "EXPOSURE", "host.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }

    @Test
    void activelyExploitedExposure_firesWithKevFindingPlusSeparateExposureFinding() {
        List<Finding> findings = List.of(
                finding("TECH_KNOWN_EXPLOITED_VULNERABILITY", "CRITICAL", "EXPOSURE", "host.example.com"),
                finding("EXPOSURE_SWAGGER_UI", "MEDIUM", "EXPOSURE", "host.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches).anySatisfy(
                m -> assertThat(m.pattern().ruleId()).isEqualTo("COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE"));
    }

    @Test
    void multipleDistinctPatternsCanFireSimultaneouslyOnTheSameAsset() {
        // GIT_CONFIG + ENV_FILE + an open admin port together should fire BOTH
        // COMPOUND_CREDENTIAL_TO_DATA_PIVOT (git-config satisfies the credentials group) AND
        // COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE (git-config + env-file specifically) -
        // legitimately two different attack narratives from the same underlying findings.
        List<Finding> findings = List.of(
                finding("EXPOSURE_GIT_CONFIG", "CRITICAL", "EXPOSURE", "api.example.com"),
                finding("EXPOSURE_ENV_FILE", "CRITICAL", "EXPOSURE", "api.example.com"),
                finding("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "HIGH", "NETWORK", "api.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches.stream().map(m -> m.pattern().ruleId()))
                .contains("COMPOUND_CREDENTIAL_TO_DATA_PIVOT", "COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE");
    }

    @Test
    void existingCompoundCategoryFindingsAreExcludedFromTriggeringFurtherPatterns() {
        // A finding already synthesized as a compound result (category COMPOUND) must never
        // itself count as a trigger for another pattern, even if its ruleId happens to match one -
        // this is what prevents compound findings from chaining into further compound findings.
        List<Finding> findings = List.of(
                finding("EXPOSURE_ENV_FILE", "CRITICAL", "COMPOUND", "api.example.com"),
                finding("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "HIGH", "NETWORK", "api.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }

    @Test
    void interceptableAdminAccess_firesWithAdminConsolePlusWeakTls() {
        List<Finding> findings = List.of(
                finding("EXPOSURE_PHPMYADMIN", "HIGH", "EXPOSURE", "legacy.example.com"),
                finding("TLS_WEAK_PROTOCOL_SUPPORTED", "HIGH", "TLS", "legacy.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches).anySatisfy(
                m -> assertThat(m.pattern().ruleId()).isEqualTo("COMPOUND_INTERCEPTABLE_ADMIN_ACCESS"));
    }

    @Test
    void sourceAndCredentialExposure_firesWithGitConfigAndEnvFileTogether() {
        List<Finding> findings = List.of(
                finding("EXPOSURE_GIT_CONFIG", "CRITICAL", "EXPOSURE", "old.example.com"),
                finding("EXPOSURE_ENV_FILE", "CRITICAL", "EXPOSURE", "old.example.com"));

        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(findings);

        assertThat(matches).anySatisfy(
                m -> assertThat(m.pattern().ruleId()).isEqualTo("COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE"));
    }

    @Test
    void noPatternsFireOnCompletelyUnrelatedFindings() {
        List<Finding> findings = List.of(
                finding("HEADER_CSP_MISSING", "MEDIUM", "HEADERS", "host.example.com"),
                finding("DNS_SPF_MISSING", "HIGH", "DNS", "host.example.com"));

        assertThat(CompoundRiskEngine.evaluate(findings)).isEmpty();
    }
}
