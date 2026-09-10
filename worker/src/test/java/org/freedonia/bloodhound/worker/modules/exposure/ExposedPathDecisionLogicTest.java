package org.freedonia.bloodhound.worker.modules.exposure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class ExposedPathDecisionLogicTest {

    private static final ProbeResponse BASELINE_404 = new ProbeResponse(404, "text/html", 9L, "not found");
    private static final String HOST = "example.com";

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    private static ExposedPathFetchResult resultWith(ProbeResponse baseline, Map<String, ProbeResponse> responses) {
        return new ExposedPathFetchResult(baseline, responses, null);
    }

    @Test
    void hostUnreachable_baselineNeverConnected_reportedAsUnreachable() {
        ExposedPathFetchResult result = resultWith(ProbeResponse.unreachable(), Map.of());
        assertThat(ExposedPathDecisionLogic.isHostUnreachable(result)).isTrue();
    }

    @Test
    void hostReachable_baselineGot404_notReportedAsUnreachable() {
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of());
        assertThat(ExposedPathDecisionLogic.isHostUnreachable(result)).isFalse();
    }

    @Test
    void allNegative_noFindings() {
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_ACTUATOR_ENV", new ProbeResponse(404, "text/html", 9L, "not found"),
                "EXPOSURE_GIT_CONFIG", new ProbeResponse(200, "text/html", 20L, "<html>a real site</html>")));
        assertThat(ExposedPathDecisionLogic.decide(HOST, result)).isEmpty();
    }

    @Test
    void actuatorEnvExposed_flaggedCritical() {
        String body = "{\"propertySources\":[{\"name\":\"applicationConfig\"}]}";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ACTUATOR_ENV", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_ACTUATOR_ENV");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
            assertThat(f.affectedAsset()).isEqualTo(HOST);
        });
    }

    /**
     * A live report: the finding said an API schema was exposed but gave no way to see where,
     * forcing a manual guess-and-check of every path this module probes. The evidence must carry
     * the exact URL the positive response actually came from.
     */
    @Test
    void exposedFinding_evidenceIncludesTheExactUrlProbed() {
        String body = "{\"propertySources\":[{\"name\":\"applicationConfig\"}]}";
        String probedUrl = "https://" + HOST + "/actuator/env";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404,
                Map.of("EXPOSURE_ACTUATOR_ENV", new ProbeResponse(200, "application/json", (long) body.length(), body, probedUrl)));

        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);

        assertThat(findings).anySatisfy(f -> assertThat(f.evidence()).containsEntry("url", probedUrl));
    }

    /**
     * The critical correctness requirement: a soft-404 site that 200s every path with an identical
     * catch-all body must never produce a finding, even if that catch-all body happens to contain
     * text that would otherwise satisfy a rule's positive signature.
     */
    @Test
    void softDupeOfBaseline_neverFlaggedEvenIfBodyContainsSignatureText() {
        String catchAllBody = "<html>this SPA catch-all page mentions propertySources in its marketing copy</html>";
        ProbeResponse baseline = new ProbeResponse(200, "text/html", (long) catchAllBody.length(), catchAllBody);
        ProbeResponse probe = new ProbeResponse(200, "text/html", (long) catchAllBody.length(), catchAllBody);
        ExposedPathFetchResult result = resultWith(baseline, Map.of("EXPOSURE_ACTUATOR_ENV", probe));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_ACTUATOR_ENV");
    }

    @Test
    void heapdump_octetStreamContentType_flagged() {
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ACTUATOR_HEAPDUMP", new ProbeResponse(200, "application/octet-stream", 5_000_000L, "")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).contains("EXPOSURE_ACTUATOR_HEAPDUMP");
    }

    @Test
    void heapdump_jsonContentType_notFlagged() {
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ACTUATOR_HEAPDUMP", new ProbeResponse(200, "application/json", 40L, "")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_ACTUATOR_HEAPDUMP");
    }

    @Test
    void actuatorIndex_onlyFiresWhenNoSubpathFired() {
        String indexBody = "{\"_links\":{\"self\":{}}}";
        Map<String, ProbeResponse> onlyIndex =
                Map.of("EXPOSURE_ACTUATOR_INDEX", new ProbeResponse(200, "application/json", (long) indexBody.length(), indexBody));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, resultWith(BASELINE_404, onlyIndex))))
                .contains("EXPOSURE_ACTUATOR_INDEX");

        String envBody = "{\"propertySources\":[]}";
        Map<String, ProbeResponse> indexPlusEnv = Map.of(
                "EXPOSURE_ACTUATOR_INDEX", new ProbeResponse(200, "application/json", (long) indexBody.length(), indexBody),
                "EXPOSURE_ACTUATOR_ENV", new ProbeResponse(200, "application/json", (long) envBody.length(), envBody));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, resultWith(BASELINE_404, indexPlusEnv))))
                .doesNotContain("EXPOSURE_ACTUATOR_INDEX")
                .contains("EXPOSURE_ACTUATOR_ENV");
    }

    @Test
    void envFile_secretShapedContent_flagged() {
        String body = "DB_PASSWORD=hunter2\nAPP_NAME=widgets\n";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ENV_FILE", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).contains("EXPOSURE_ENV_FILE");
    }

    @Test
    void envFile_htmlErrorPageNamedEnv_notFlagged() {
        String body = "<html><body>404 not found</body></html>";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ENV_FILE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_ENV_FILE");
    }

    @Test
    void envFile_plainTextWithoutSecretShapedKeys_notFlagged() {
        String body = "APP_NAME=widgets\nAPP_ENV=production\n";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ENV_FILE", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_ENV_FILE");
    }

    @Test
    void dockerApi_positiveJsonShape_flaggedWithPortInAssetName() {
        String body = "{\"ApiVersion\":\"1.45\",\"Version\":\"24.0.0\"}";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_DOCKER_API", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_DOCKER_API");
            assertThat(f.affectedAsset()).isEqualTo("example.com:2375");
        });
    }

    @Test
    void redis_bulkStringInfoReply_flaggedCritical() {
        ExposedPathFetchResult result = new ExposedPathFetchResult(
                BASELINE_404, Map.of(), "$2500\r\n# Server\r\nredis_version:7.2.4\r\n...");
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_REDIS_UNAUTH");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
            assertThat(f.affectedAsset()).isEqualTo("example.com:6379");
        });
    }

    @Test
    void redis_noauthRefusal_notFlagged() {
        ExposedPathFetchResult result = new ExposedPathFetchResult(BASELINE_404, Map.of(), "-NOAUTH Authentication required.\r\n");
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_REDIS_UNAUTH");
    }

    @Test
    void redis_unreachable_notFlagged() {
        ExposedPathFetchResult result = new ExposedPathFetchResult(BASELINE_404, Map.of(), null);
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_REDIS_UNAUTH");
    }

    /**
     * Real false positive found during Milestone 9's live verification: github.com/phpmyadmin
     * resolves to the real phpMyAdmin project's GitHub org page (a 200, unrelated to any exposed
     * console) and its body legitimately contains the literal text "phpMyAdmin" many times. A bare
     * body-substring check alone would wrongly flag this; the rule must also require the login
     * form's distinctive field name.
     */
    @Test
    void phpMyAdmin_textPresentWithoutLoginFormMarker_notFlagged() {
        String body = "<html><body>Welcome to the phpMyAdmin project on GitHub. Star us!</body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_PHPMYADMIN", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_PHPMYADMIN");
    }

    @Test
    void phpMyAdmin_realLoginForm_flaggedHigh() {
        String body = "<html><title>phpMyAdmin</title><body><form><input name=\"pma_username\"></form></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_PHPMYADMIN", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_PHPMYADMIN");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void envFile_secretShapedContent_alsoTripsLiveSecretDetected() {
        String body = "DB_PASSWORD=hunter2\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\n";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ENV_FILE", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_ENV_FILE", "EXPOSURE_LIVE_SECRET_DETECTED");
        RawFinding secretFinding = findings.stream()
                .filter(f -> f.ruleId().equals("EXPOSURE_LIVE_SECRET_DETECTED"))
                .findFirst()
                .orElseThrow();
        assertThat(secretFinding.severity().name()).isEqualTo("CRITICAL");
        assertThat(secretFinding.affectedAsset()).isEqualTo("example.com (.env)");
        assertThat(secretFinding.evidence()).containsEntry("sourceFile", ".env");
        @SuppressWarnings("unchecked")
        List<String> patternsFound = (List<String>) secretFinding.evidence().get("patternsFound");
        assertThat(patternsFound).contains("AWS Access Key ID");
    }

    @Test
    void envFile_secretShapedKeyNameButNoLiveLookingValue_onlyEnvFileFinding_noSecretDetected() {
        String body = "DB_PASSWORD=hunter2\nAPP_NAME=widgets\n";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_ENV_FILE", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_ENV_FILE").doesNotContain("EXPOSURE_LIVE_SECRET_DETECTED");
    }

    @Test
    void gitConfig_withCredentialEmbeddedUrl_tripsLiveSecretDetectedWithGitConfigLabel() {
        String body = "[core]\nrepositoryformatversion = 0\n[remote \"origin\"]\n"
                + "url = https://deploy:hunter2verylongtoken@github.com/example/repo.git\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_GIT_CONFIG", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_GIT_CONFIG", "EXPOSURE_LIVE_SECRET_DETECTED");
        RawFinding secretFinding = findings.stream()
                .filter(f -> f.ruleId().equals("EXPOSURE_LIVE_SECRET_DETECTED"))
                .findFirst()
                .orElseThrow();
        assertThat(secretFinding.affectedAsset()).isEqualTo("example.com (.git/config)");
    }

    @Test
    void awsCredentials_withSecretKey_tripsLiveSecretDetectedWithAwsCredentialsLabel() {
        String body = "[default]\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\n"
                + "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_AWS_CREDENTIALS", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_AWS_CREDENTIALS", "EXPOSURE_LIVE_SECRET_DETECTED");
        RawFinding secretFinding = findings.stream()
                .filter(f -> f.ruleId().equals("EXPOSURE_LIVE_SECRET_DETECTED"))
                .findFirst()
                .orElseThrow();
        assertThat(secretFinding.affectedAsset()).isEqualTo("example.com (.aws/credentials)");
    }

    @Test
    void actuatorThreaddumpLoggersIndex_flaggedHigh() {
        String threaddumpBody = "{\"threads\":[{\"threadName\":\"main\"}]}";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_ACTUATOR_THREADDUMP",
                new ProbeResponse(200, "application/json", (long) threaddumpBody.length(), threaddumpBody)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_ACTUATOR_THREADDUMP");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void actuatorHealth_actuatorContentType_flaggedInfo() {
        String body = "{}";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_ACTUATOR_HEALTH",
                new ProbeResponse(200, "application/vnd.spring-boot.actuator.v3+json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_ACTUATOR_HEALTH");
            assertThat(f.severity().name()).isEqualTo("INFO");
        });
    }

    @Test
    void actuatorHealth_plainJsonWithStatusUp_stillFlaggedViaBodyFallback() {
        String body = "{\"status\":\"UP\"}";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ACTUATOR_HEALTH", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).contains("EXPOSURE_ACTUATOR_HEALTH");
    }

    /**
     * A live finding showed the gap this closes: a bare {"status":"UP"} and a full component
     * breakdown (disk paths, capacity, DB/SSL state) were both reported as the same INFO-severity
     * EXPOSURE_ACTUATOR_HEALTH rule. A "components" breakdown only ever appears when the operator
     * has explicitly set show-details to "always" (Spring Boot's own default is "never" for an
     * unauthenticated caller) - real internal infrastructure disclosure, not just "the endpoint
     * exists", so it's now its own MEDIUM-severity rule instead.
     */
    @Test
    void actuatorHealth_detailedComponentsBreakdown_flaggedAsDistinctMediumRule() {
        String body = "{\"status\":\"UP\",\"components\":{\"diskSpace\":{\"status\":\"UP\","
                + "\"details\":{\"total\":751070851072,\"free\":551136649216,\"path\":\"/home/jboss/.\"}}}}";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_ACTUATOR_HEALTH",
                new ProbeResponse(200, "application/vnd.spring-boot.actuator.v3+json", (long) body.length(), body)));

        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);

        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_ACTUATOR_HEALTH_DETAILS");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
        // Exclusive, not additive - one URL, one finding; the bare-status rule must not also fire.
        assertThat(ruleIds(findings)).doesNotContain("EXPOSURE_ACTUATOR_HEALTH");
    }

    @Test
    void actuatorInfo_actuatorContentType_flaggedInfo() {
        String body = "{\"build\":{\"version\":\"1.0.0\"}}";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_ACTUATOR_INFO",
                new ProbeResponse(200, "application/vnd.spring-boot.actuator.v3+json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_ACTUATOR_INFO");
            assertThat(f.severity().name()).isEqualTo("INFO");
        });
    }

    /**
     * Unlike health (which has the "status":"UP" body fallback), an empty-ish info body has no
     * reliable content-based signature on its own - a generic API coincidentally returning "{}" on
     * plain application/json must not be flagged just because it differs from the baseline body.
     */
    @Test
    void actuatorInfo_plainJsonContentType_notFlagged() {
        String body = "{}";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ACTUATOR_INFO", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_ACTUATOR_INFO");
    }

    @Test
    void securityTxtPresent_flaggedInfoAsPositiveSignal() {
        String body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SECURITY_TXT_PRESENT", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_SECURITY_TXT_PRESENT");
            assertThat(f.severity().name()).isEqualTo("INFO");
        });
    }
}
