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

    /**
     * Real .DS_Store magic bytes (0x00000001 then ASCII "Bud1"), decoded through UTF-8 exactly the
     * way ExposedPathFetcher decodes every probe body - the leading binary bytes turn into
     * replacement characters, but "Bud1" itself (pure ASCII) survives intact, which is exactly
     * the property looksLikeDsStore relies on.
     */
    @Test
    void dsStoreMagicBytes_flaggedMediumEvenThroughLossyUtf8Decode() {
        byte[] realDsStoreHeader = {0x00, 0x00, 0x00, 0x01, 'B', 'u', 'd', '1', 0x00, 0x10, 0x00, 0x00};
        String body = new String(realDsStoreHeader, java.nio.charset.StandardCharsets.UTF_8);
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_DS_STORE", new ProbeResponse(200, "application/octet-stream", (long) realDsStoreHeader.length, body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_DS_STORE");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
    }

    @Test
    void notDsStoreFormat_notFlagged() {
        String body = "<html><body>404 not found</body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_DS_STORE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_DS_STORE");
    }

    /** The exact real nginx autoindex response captured live from the juiceshop-proxy dev fixture. */
    private static final String REAL_NGINX_AUTOINDEX_BODY =
            "<html>\n<head><title>Index of /bh-test-listing/</title></head>\n<body>\n"
                    + "<h1>Index of /bh-test-listing/</h1><hr><pre><a href=\"../\">../</a>\n"
                    + "<a href=\"backup.sql.bak\">backup.sql.bak</a>                                     "
                    + "14-Sep-2026 17:52                  26\n"
                    + "<a href=\"notes.txt\">notes.txt</a>                                          "
                    + "14-Sep-2026 17:52                  57\n</pre><hr></body>\n</html>";

    @Test
    void realNginxAutoindexResponse_flaggedMedium() {
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_DIRECTORY_LISTING",
                new ProbeResponse(200, "text/html", (long) REAL_NGINX_AUTOINDEX_BODY.length(), REAL_NGINX_AUTOINDEX_BODY)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_DIRECTORY_LISTING");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
    }

    /** Apache's mod_autoindex uses a differently-structured (table, not <pre>) page but the same title/heading phrasing. */
    @Test
    void apacheStyleAutoindexResponse_alsoFlagged() {
        String body = "<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1>"
                + "<table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>"
                + "<tr><td><a href=\"db.sql\">db.sql</a></td></tr></table></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_DIRECTORY_LISTING", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).contains("EXPOSURE_DIRECTORY_LISTING");
    }

    @Test
    void notADirectoryListing_notFlagged() {
        String body = "<html><body><h1>Welcome to our backup service page</h1></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_DIRECTORY_LISTING", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_DIRECTORY_LISTING");
    }

    /** A soft-404 SPA catch-all that happens to 200 every guessed directory path must never be flagged. */
    @Test
    void directoryListingProbe_softDupeOfBaseline_notFlagged() {
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_DIRECTORY_LISTING", new ProbeResponse(200, "text/html", 9L, "not found")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_DIRECTORY_LISTING");
    }

    @Test
    void backupArchive_zipMagicBytes_flaggedCritical() {
        String body = "PK" + "rest of a real zip's local file header, not valid UTF-8 in practice";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_BACKUP_ARCHIVE", new ProbeResponse(200, "application/octet-stream", 40L, body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_BACKUP_ARCHIVE");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void backupArchive_gzipContentTypeNoMagicBytesInBody_stillFlagged() {
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_BACKUP_ARCHIVE", new ProbeResponse(200, "application/gzip", 40L, "unreadable binary")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).contains("EXPOSURE_BACKUP_ARCHIVE");
    }

    @Test
    void backupArchive_plainHtmlNotAnArchive_notFlagged() {
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_BACKUP_ARCHIVE", new ProbeResponse(200, "text/html", 20L, "<html>a real site</html>")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_BACKUP_ARCHIVE");
    }

    @Test
    void sqlDumpFile_mysqlDumpHeader_flaggedCritical() {
        String body = "-- MySQL dump 10.13  Distrib 8.0.33\nCREATE TABLE `users` (...);\nINSERT INTO `users` VALUES (1);";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_SQL_DUMP_FILE", new ProbeResponse(200, "application/sql", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_SQL_DUMP_FILE");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void sqlDumpFile_unrelatedPageMentioningCreateTable_notFlagged() {
        String body = "<html><body>Our docs explain how to use CREATE TABLE in SQL.</body></html>";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_SQL_DUMP_FILE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_SQL_DUMP_FILE");
    }

    @Test
    void phpInfo_realPhpinfoMarkers_flaggedHigh() {
        String body = "<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.2.1</h1></body></html>";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_PHP_INFO", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_PHP_INFO");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void sshPrivateKey_pemHeader_flaggedCritical() {
        String body = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_SSH_PRIVATE_KEY", new ProbeResponse(200, "application/octet-stream", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_SSH_PRIVATE_KEY");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void prometheusMetrics_realExpositionFormat_flaggedMedium() {
        String body = "# HELP http_requests_total Total HTTP requests\n# TYPE http_requests_total counter\nhttp_requests_total 1027";
        ExposedPathFetchResult result =
                resultWith(BASELINE_404, Map.of("EXPOSURE_PROMETHEUS_METRICS", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_PROMETHEUS_METRICS");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
    }

    @Test
    void prometheusMetrics_plainTextWithoutExpositionMarkers_notFlagged() {
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_PROMETHEUS_METRICS", new ProbeResponse(200, "text/plain", 20L, "just some plain text")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_PROMETHEUS_METRICS");
    }

    @Test
    void jsSourceMap_genuineSourceMapShape_flaggedMedium() {
        String body = "{\"version\":3,\"sources\":[\"webpack:///./src/App.js\"],\"mappings\":\"AAAA\"}";
        ExposedPathFetchResult result = new ExposedPathFetchResult(
                BASELINE_404,
                Map.of(),
                null,
                Map.of("https://example.com/static/main.abc123.js", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_JS_SOURCE_MAP");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
            assertThat(f.affectedAsset()).isEqualTo("https://example.com/static/main.abc123.js.map");
        });
    }

    @Test
    void jsSourceMap_404Response_notFlagged() {
        ExposedPathFetchResult result = new ExposedPathFetchResult(
                BASELINE_404,
                Map.of(),
                null,
                Map.of("https://example.com/static/main.abc123.js", new ProbeResponse(404, "text/html", 9L, "not found")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_JS_SOURCE_MAP");
    }

    @Test
    void jsSourceMap_200ButNotSourceMapShaped_notFlagged() {
        ExposedPathFetchResult result = new ExposedPathFetchResult(
                BASELINE_404,
                Map.of(),
                null,
                Map.of("https://example.com/static/main.abc123.js", new ProbeResponse(200, "text/html", 20L, "<html>a real site</html>")));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_JS_SOURCE_MAP");
    }

    @Test
    void h2Console_realMarkers_flaggedCritical() {
        String body = "<html><body><h1>H2 Console</h1><form><input name=\"Driver Class\"></form></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SPRING_BOOT_H2_CONSOLE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_SPRING_BOOT_H2_CONSOLE");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void h2Console_onlyOneMarkerPresent_notFlagged() {
        String body = "<html><body><h1>H2 Console</h1></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SPRING_BOOT_H2_CONSOLE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_SPRING_BOOT_H2_CONSOLE");
    }

    @Test
    void laravelTelescope_rootDivMarker_flaggedHigh() {
        String body = "<html><body><div id=\"telescope\"></div></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_LARAVEL_TELESCOPE", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_LARAVEL_TELESCOPE");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void aspNetTraceAxd_realMarkers_flaggedHigh() {
        String body = "<html><body><h1>Application Trace</h1><p>Requests to the Application</p></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ASPNET_TRACE_AXD", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("EXPOSURE_ASPNET_TRACE_AXD"));
    }

    @Test
    void aspNetElmah_errorLogMarker_flaggedHigh() {
        String body = "<html><body><h1>Error Log for /site</h1></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ASPNET_ELMAH", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("EXPOSURE_ASPNET_ELMAH"));
    }

    @Test
    void adminer_loginFormFieldMarker_flaggedHigh() {
        String body = "<html><body><form><select name=\"auth[driver]\"></select></form></body></html>";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_ADMINER", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("EXPOSURE_ADMINER"));
    }

    @Test
    void laravelDebugMode_whoopsMarkers_flaggedOnBaselineResponse() {
        String body = "<html><body><div class=\"whoops-container\">Whoops! There was an error.</div></body></html>";
        ExposedPathFetchResult result = resultWith(
                new ProbeResponse(404, "text/html", (long) body.length(), body), Map.of());
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_LARAVEL_DEBUG_MODE");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void laravelDebugMode_ignitionMarkers_flaggedOnBaselineResponse() {
        String body = "<html><body>Ignition<pre>Illuminate\\Foundation\\Application::run</pre></body></html>";
        ExposedPathFetchResult result = resultWith(
                new ProbeResponse(500, "text/html", (long) body.length(), body), Map.of());
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("EXPOSURE_LARAVEL_DEBUG_MODE"));
    }

    @Test
    void laravelDebugMode_ordinary404Page_notFlagged() {
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of());
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_LARAVEL_DEBUG_MODE");
    }

    @Test
    void grafanaAltPort_positiveJsonShape_flaggedWithPortInAssetName() {
        String body = "{\"database\":\"ok\",\"version\":\"10.4.2\"}";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_GRAFANA_UNAUTH", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_GRAFANA_UNAUTH");
            assertThat(f.affectedAsset()).isEqualTo("example.com:3000");
        });
    }

    @Test
    void mongoExpressAltPort_positiveMarker_flaggedCriticalWithPortInAssetName() {
        String body = "<html><head><title>Mongo Express</title></head><body></body></html>";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_MONGO_EXPRESS_UNAUTH", new ProbeResponse(200, "text/html", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_MONGO_EXPRESS_UNAUTH");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
            assertThat(f.affectedAsset()).isEqualTo("example.com:8081");
        });
    }

    @Test
    void traefikAltPort_positiveJsonShape_flaggedWithPortInAssetName() {
        String body = "{\"backends\":{},\"frontends\":{}}";
        ExposedPathFetchResult result = resultWith(BASELINE_404, Map.of(
                "EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH", new ProbeResponse(200, "application/json", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH");
            assertThat(f.affectedAsset()).isEqualTo("example.com:8080");
        });
    }

    @Test
    void securityTxtExpired_pastExpiresDate_flaggedInfo() {
        String body = "Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SECURITY_TXT_PRESENT", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_SECURITY_TXT_PRESENT", "EXPOSURE_SECURITY_TXT_EXPIRED");
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EXPOSURE_SECURITY_TXT_EXPIRED");
            assertThat(f.severity().name()).isEqualTo("INFO");
        });
    }

    @Test
    void securityTxtNotExpired_futureExpiresDate_onlyPresentFindingFires() {
        String body = "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SECURITY_TXT_PRESENT", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        List<RawFinding> findings = ExposedPathDecisionLogic.decide(HOST, result);
        assertThat(ruleIds(findings)).contains("EXPOSURE_SECURITY_TXT_PRESENT").doesNotContain("EXPOSURE_SECURITY_TXT_EXPIRED");
    }

    @Test
    void securityTxtNoExpiresLine_notFlaggedExpired() {
        String body = "Contact: mailto:security@example.com\n";
        ExposedPathFetchResult result = resultWith(
                BASELINE_404, Map.of("EXPOSURE_SECURITY_TXT_PRESENT", new ProbeResponse(200, "text/plain", (long) body.length(), body)));
        assertThat(ruleIds(ExposedPathDecisionLogic.decide(HOST, result))).doesNotContain("EXPOSURE_SECURITY_TXT_EXPIRED");
    }
}
