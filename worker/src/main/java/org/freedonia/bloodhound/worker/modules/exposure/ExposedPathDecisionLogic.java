package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of an already-fetched {@link ExposedPathFetchResult}
 * into findings - no network calls, fully unit-testable.
 *
 * <p>Every content-bearing check requires BOTH a 200 status AND a specific
 * positive body/header signature (never status-code-alone), and for
 * default-port probes the matched body must differ from the baseline
 * (soft-404) probe's body - a site that 200s every path with an identical
 * catch-all page can never trigger a finding here, since its body can never
 * simultaneously equal the baseline body and contain e.g.
 * {@code "propertySources"}.
 *
 * <p>When the .env, .git/config, or AWS-credentials check fires, its
 * already-fetched body is additionally re-checked by {@link
 * SecretPatternScanner} for live-looking credential formats - see {@link
 * #addSecretScanFinding}. No new network calls; this only sharpens "a file
 * is exposed" into "here's what's actually in it."
 */
public final class ExposedPathDecisionLogic {

    private static final List<String> ACTUATOR_SUBPATH_RULES = List.of(
            "EXPOSURE_ACTUATOR_HEAPDUMP",
            "EXPOSURE_ACTUATOR_ENV",
            "EXPOSURE_ACTUATOR_BEANS",
            "EXPOSURE_ACTUATOR_MAPPINGS",
            "EXPOSURE_ACTUATOR_CONFIGPROPS",
            "EXPOSURE_ACTUATOR_THREADDUMP",
            "EXPOSURE_ACTUATOR_LOGGERS");

    private ExposedPathDecisionLogic() {}

    /**
     * The baseline probe (a definitely-nonexistent random path) uses the exact
     * same connection logic as every other probe in the catalog - if it
     * couldn't even connect, the host is unreachable and none of the other
     * ~20 probes could have meaningfully run either, even though each one
     * individually "completed" with an unreachable() response. Callers use
     * this to distinguish a genuine clean scan (host responded, nothing
     * matched) from a silent no-op that would otherwise report the same
     * "ran N probes, found nothing" shape.
     */
    public static boolean isHostUnreachable(ExposedPathFetchResult result) {
        return !result.baseline().isReachable();
    }

    public static List<RawFinding> decide(String hostname, ExposedPathFetchResult result) {
        List<RawFinding> findings = new ArrayList<>();
        Map<String, ProbeResponse> r = result.responses();
        String baselineBody = result.baseline().body();

        boolean anyActuatorSubpathFired = false;
        for (String ruleId : ACTUATOR_SUBPATH_RULES) {
            if ("EXPOSURE_ACTUATOR_HEAPDUMP".equals(ruleId)) {
                if (isHeapdumpPositive(r.get(ruleId))) {
                    findings.add(finding(ruleId, hostname, r.get(ruleId)));
                    anyActuatorSubpathFired = true;
                }
                continue;
            }
            String marker = switch (ruleId) {
                case "EXPOSURE_ACTUATOR_ENV" -> "\"propertySources\"";
                case "EXPOSURE_ACTUATOR_BEANS" -> "\"beans\"";
                case "EXPOSURE_ACTUATOR_MAPPINGS" -> null; // handled below, two possible markers
                case "EXPOSURE_ACTUATOR_CONFIGPROPS" -> null; // handled below, two possible markers
                case "EXPOSURE_ACTUATOR_THREADDUMP" -> "\"threadName\"";
                case "EXPOSURE_ACTUATOR_LOGGERS" -> "\"loggers\"";
                default -> null;
            };
            Predicate<String> positive = switch (ruleId) {
                case "EXPOSURE_ACTUATOR_MAPPINGS" -> b -> b.contains("\"contexts\"") || b.contains("\"dispatcherServlets\"");
                case "EXPOSURE_ACTUATOR_CONFIGPROPS" -> b -> b.contains("\"contexts\"") || b.contains("\"beans\"");
                default -> b -> marker != null && b.contains(marker);
            };
            if (matches(r.get(ruleId), baselineBody, positive)) {
                findings.add(finding(ruleId, hostname, r.get(ruleId)));
                anyActuatorSubpathFired = true;
            }
        }
        if (!anyActuatorSubpathFired && matches(r.get("EXPOSURE_ACTUATOR_INDEX"), baselineBody, b -> b.contains("\"_links\""))) {
            findings.add(finding("EXPOSURE_ACTUATOR_INDEX", hostname, r.get("EXPOSURE_ACTUATOR_INDEX")));
        }

        // Deliberately NOT gated by anyActuatorSubpathFired like the bare index above: health/info being
        // reachable doesn't make the index finding redundant (or vice versa) - each is independently
        // useful, and these two are reported at INFO severity precisely because they're near-universally
        // intentional (load balancer health checks, build-info banners), unlike the rest of the actuator
        // surface.
        //
        // /actuator/health is the one exception within that INFO-by-default pair: Spring Boot's own
        // default for management.endpoint.health.show-details is "never", so an unauthenticated caller
        // seeing a bare {"status":"UP"} tells you nothing an LB health check wouldn't already show. A
        // "components" breakdown, though, only ever appears when the operator has explicitly set
        // show-details to "always" (or an authorization check meant to gate "when-authorized" isn't
        // actually being enforced for this caller) - and that breakdown routinely includes real internal
        // state: absolute filesystem paths, disk free/total capacity, DB/SSL component status. That's a
        // genuine information-disclosure step up from "the endpoint exists", so it's reported as its own,
        // more severe rule rather than folded into the bare-status case.
        ProbeResponse healthResponse = r.get("EXPOSURE_ACTUATOR_HEALTH");
        if (matches(healthResponse, baselineBody,
                b -> isActuatorContentType(healthResponse) || looksLikeActuatorHealthBody(b))) {
            String healthRuleId = healthResponse.body().contains("\"components\"")
                    ? "EXPOSURE_ACTUATOR_HEALTH_DETAILS"
                    : "EXPOSURE_ACTUATOR_HEALTH";
            findings.add(finding(healthRuleId, hostname, healthResponse));
        }
        addIfMatches(findings, hostname, r, "EXPOSURE_ACTUATOR_INFO", baselineBody,
                b -> isActuatorContentType(r.get("EXPOSURE_ACTUATOR_INFO")));

        if (addIfMatches(findings, hostname, r, "EXPOSURE_GIT_CONFIG", baselineBody,
                b -> b.contains("[core]") && b.contains("repositoryformatversion"))) {
            addSecretScanFinding(findings, hostname, r.get("EXPOSURE_GIT_CONFIG"), ".git/config");
        }
        if (addIfMatches(findings, hostname, r, "EXPOSURE_ENV_FILE", baselineBody, ExposedPathDecisionLogic::looksLikeEnvFile)) {
            addSecretScanFinding(findings, hostname, r.get("EXPOSURE_ENV_FILE"), ".env");
        }
        if (addIfMatches(findings, hostname, r, "EXPOSURE_AWS_CREDENTIALS", baselineBody, b -> b.contains("aws_access_key_id"))) {
            addSecretScanFinding(findings, hostname, r.get("EXPOSURE_AWS_CREDENTIALS"), ".aws/credentials");
        }
        addIfMatches(findings, hostname, r, "EXPOSURE_SWAGGER_UI", baselineBody,
                b -> b.contains("\"swagger\"") || b.contains("\"openapi\""));
        addIfMatches(findings, hostname, r, "EXPOSURE_GRAPHQL_INTROSPECTION", baselineBody, b -> b.contains("__schema"));
        // A bare "phpMyAdmin" body substring is not a safe signature on its own: large
        // multi-tenant platforms (e.g. GitHub, where /phpmyadmin resolves to the real
        // phpMyAdmin project's org page) can 200 with that literal text present for
        // reasons unrelated to an actual exposed console - found as a real false
        // positive during Milestone 9's live verification against github.com. Require
        // the login form's distinctive field name too, per the original spec's intent
        // ("phpMyAdmin" text AND a recognizable login-form marker).
        addIfMatches(findings, hostname, r, "EXPOSURE_PHPMYADMIN", baselineBody,
                b -> b.contains("phpMyAdmin") && b.contains("pma_username"));
        addIfMatches(findings, hostname, r, "EXPOSURE_JENKINS_SCRIPT", baselineBody,
                b -> b.contains("Groovy script") || b.contains("Script Console"));
        addIfMatches(findings, hostname, r, "EXPOSURE_KIBANA_UNAUTH", baselineBody, b -> b.contains("kbn-injected-metadata"));
        addIfMatches(findings, hostname, r, "EXPOSURE_SECURITY_TXT_PRESENT", baselineBody, b -> b.contains("Contact:"));

        // Alt-port probes: different port/protocol than the baseline probe, so no soft-404-dupe guard applies -
        // the content signature (a specific JSON shape) is the sole, sufficient guard here.
        addAltPortIfMatches(findings, hostname + ":2375", r, "EXPOSURE_DOCKER_API", b -> b.contains("\"ApiVersion\""));
        addAltPortIfMatches(findings, hostname + ":9200", r, "EXPOSURE_ELASTICSEARCH_UNAUTH",
                b -> b.contains("\"cluster_name\"") || b.contains("you_know_for_search"));
        addAltPortIfMatches(findings, hostname + ":8500", r, "EXPOSURE_CONSUL_UNAUTH",
                b -> b.trim().matches("(?s)\"[0-9.]+:[0-9]+\""));

        if (isRedisPositive(result.redisResponse())) {
            findings.add(finding("EXPOSURE_REDIS_UNAUTH", hostname + ":6379", Map.of()));
        }

        return findings;
    }

    private static boolean matches(ProbeResponse response, String baselineBody, Predicate<String> positive) {
        if (response == null || response.status() != 200 || response.body() == null) {
            return false;
        }
        if (Objects.equals(response.body(), baselineBody)) {
            return false; // soft-404: identical to what a nonexistent path returns
        }
        return positive.test(response.body());
    }

    /**
     * Spring Boot Actuator, by default, answers with the {@code
     * vnd.spring-boot.actuator.v2+json}/{@code v3+json} content type when no
     * explicit {@code Accept} header is sent (this codebase never sends
     * one) - a signature specific to actuator itself, not just "this looks
     * like JSON that happens to contain a status field." Used for
     * health/info, where the body alone (an unauthenticated {@code
     * {"status":"UP"}} or even {@code {}}) is otherwise too generic a
     * signature to trust on its own.
     */
    private static boolean isActuatorContentType(ProbeResponse response) {
        return response != null
                && response.status() == 200
                && response.contentType() != null
                && response.contentType().toLowerCase(Locale.ROOT).contains("vnd.spring-boot.actuator");
    }

    /** Fallback for actuator/health when content negotiation still returned plain application/json. */
    private static boolean looksLikeActuatorHealthBody(String body) {
        return body.contains("\"status\":\"UP\"")
                || body.contains("\"status\":\"DOWN\"")
                || body.contains("\"status\":\"OUT_OF_SERVICE\"")
                || body.contains("\"status\":\"UNKNOWN\"");
    }

    private static boolean isHeapdumpPositive(ProbeResponse response) {
        // Body is never downloaded for this probe (see ExposedPathFetcher) - content-type is the sole,
        // deliberately strict signal, avoiding both a soft-404 false-positive and ever pulling a
        // multi-gigabyte heap dump into memory just to look at it.
        return response != null
                && response.status() == 200
                && response.contentType() != null
                && response.contentType().toLowerCase(Locale.ROOT).contains("octet-stream");
    }

    private static boolean addIfMatches(
            List<RawFinding> findings, String hostname, Map<String, ProbeResponse> r, String ruleId, String baselineBody,
            Predicate<String> positive) {
        if (matches(r.get(ruleId), baselineBody, positive)) {
            findings.add(finding(ruleId, hostname, r.get(ruleId)));
            return true;
        }
        return false;
    }

    /**
     * Re-greps a body already fetched (and already found to trip its own
     * exposure rule) for live-looking secret formats - see
     * {@link SecretPatternScanner}. Reported as a distinct finding rather
     * than folded into the parent one, with the source file appended to the
     * affected asset ({@code hostname + " (" + fileLabel + ")"}) so
     * .env/.git/config/.aws/credentials findings on the same hostname get
     * independent dedup keys, matching the alt-port precedent used for
     * EXPOSURE_DOCKER_API/EXPOSURE_ELASTICSEARCH_UNAUTH above.
     */
    private static void addSecretScanFinding(
            List<RawFinding> findings, String hostname, ProbeResponse response, String fileLabel) {
        if (response == null || response.body() == null) {
            return;
        }
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(response.body());
        if (matches.isEmpty()) {
            return;
        }
        List<String> patternNames = matches.stream().map(SecretPatternScanner.Match::patternName).toList();
        List<String> previews = matches.stream().map(SecretPatternScanner.Match::redactedPreview).toList();
        findings.add(finding(
                "EXPOSURE_LIVE_SECRET_DETECTED",
                hostname + " (" + fileLabel + ")",
                Map.of(
                        "sourceFile", fileLabel,
                        "patternsFound", patternNames,
                        "matchCount", matches.size(),
                        "previews", previews,
                        "url", response.url() == null ? "" : response.url())));
    }

    private static void addAltPortIfMatches(
            List<RawFinding> findings, String assetWithPort, Map<String, ProbeResponse> r, String ruleId, Predicate<String> positive) {
        ProbeResponse response = r.get(ruleId);
        if (response != null && response.status() == 200 && response.body() != null && positive.test(response.body())) {
            findings.add(finding(ruleId, assetWithPort, response));
        }
    }

    /** KEY=value lines, not HTML, with at least one key that looks secret-shaped - avoids flagging arbitrary plain-text files merely named .env. */
    static boolean looksLikeEnvFile(String body) {
        if (body == null || body.isBlank() || body.stripLeading().startsWith("<")) {
            return false;
        }
        boolean anyKeyValueLine = false;
        boolean anySecretLikeKey = false;
        for (String line : body.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || !trimmed.matches("^[A-Za-z_][A-Za-z0-9_]*=.*$")) {
                continue;
            }
            anyKeyValueLine = true;
            String key = trimmed.substring(0, trimmed.indexOf('=')).toUpperCase(Locale.ROOT);
            if (key.contains("DB_") || key.contains("SECRET") || key.contains("API_KEY") || key.contains("PASSWORD")) {
                anySecretLikeKey = true;
            }
        }
        return anyKeyValueLine && anySecretLikeKey;
    }

    /** A NOAUTH/ERR refusal means "properly secured" - not a finding; only a genuine bulk-string INFO reply counts. */
    static boolean isRedisPositive(String redisResponse) {
        return redisResponse != null && redisResponse.startsWith("$") && redisResponse.contains("redis_version:");
    }

    private static RawFinding finding(String ruleId, String affectedAsset, ProbeResponse evidenceSource) {
        // "url" - a live report asked for exactly this: the finding said an API schema was
        // exposed but gave no way to see where, forcing a manual guess-and-check of every
        // Swagger/actuator/etc. path this module actually probes. evidenceSource.url() is the
        // exact request URL that produced this response, always present for anything that got
        // as far as an HTTP response (see ProbeResponse's own doc comment).
        Map<String, Object> evidence = evidenceSource == null
                ? Map.of()
                : Map.of(
                        "status", evidenceSource.status(),
                        "contentType", evidenceSource.contentType() == null ? "" : evidenceSource.contentType(),
                        "url", evidenceSource.url() == null ? "" : evidenceSource.url());
        return finding(ruleId, affectedAsset, evidence);
    }

    private static RawFinding finding(String ruleId, String affectedAsset, Map<String, Object> evidence) {
        RuleMeta meta = COPY.get(ruleId);
        return new RawFinding(ruleId, meta.severity(), Category.EXPOSURE, meta.title(), meta.description(), affectedAsset, evidence);
    }

    private record RuleMeta(Severity severity, String title, String description) {}

    private static final Map<String, RuleMeta> COPY = Map.ofEntries(
            Map.entry("EXPOSURE_ACTUATOR_HEAPDUMP", new RuleMeta(Severity.CRITICAL,
                    "Spring Boot Actuator heap dump exposed",
                    "The /actuator/heapdump endpoint is publicly reachable and can disclose secrets held in memory.")),
            Map.entry("EXPOSURE_ACTUATOR_ENV", new RuleMeta(Severity.CRITICAL,
                    "Spring Boot Actuator environment endpoint exposed",
                    "The /actuator/env endpoint is publicly reachable, often disclosing credentials/config secrets.")),
            Map.entry("EXPOSURE_ACTUATOR_BEANS", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator beans endpoint exposed",
                    "The /actuator/beans endpoint is publicly reachable, disclosing the internal application context.")),
            Map.entry("EXPOSURE_ACTUATOR_MAPPINGS", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator mappings endpoint exposed",
                    "The /actuator/mappings endpoint is publicly reachable, disclosing every request mapping.")),
            Map.entry("EXPOSURE_ACTUATOR_CONFIGPROPS", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator configprops endpoint exposed",
                    "The /actuator/configprops endpoint is publicly reachable and can disclose configuration secrets.")),
            Map.entry("EXPOSURE_ACTUATOR_THREADDUMP", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator thread dump endpoint exposed",
                    "The /actuator/threaddump endpoint is publicly reachable, disclosing JVM thread state.")),
            Map.entry("EXPOSURE_ACTUATOR_LOGGERS", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator loggers endpoint exposed",
                    "The /actuator/loggers endpoint is publicly reachable.")),
            Map.entry("EXPOSURE_ACTUATOR_INDEX", new RuleMeta(Severity.HIGH,
                    "Spring Boot Actuator index exposed",
                    "The base /actuator endpoint is publicly reachable and lists management sub-endpoints.")),
            Map.entry("EXPOSURE_ACTUATOR_HEALTH", new RuleMeta(Severity.INFO,
                    "Spring Boot Actuator health endpoint exposed",
                    "The /actuator/health endpoint is publicly reachable. This is commonly intentional (used by "
                            + "load balancers/orchestrators for health checks) and is reported for visibility only.")),
            Map.entry("EXPOSURE_ACTUATOR_HEALTH_DETAILS", new RuleMeta(Severity.MEDIUM,
                    "Spring Boot Actuator health endpoint discloses internal system details",
                    "The /actuator/health endpoint returns a detailed component breakdown (e.g. absolute "
                            + "filesystem paths, disk free/total capacity, database or SSL/certificate component "
                            + "state) to an unauthenticated caller, rather than just the overall status. Spring "
                            + "Boot's default for this is to show no component detail publicly, so this requires "
                            + "an explicit show-details=always setting or an authorization check that isn't "
                            + "actually being enforced - and it discloses real internal infrastructure detail "
                            + "useful for reconnaissance, not just \"a health check exists\".")),
            Map.entry("EXPOSURE_ACTUATOR_INFO", new RuleMeta(Severity.INFO,
                    "Spring Boot Actuator info endpoint exposed",
                    "The /actuator/info endpoint is publicly reachable. This is commonly intentional (build/version "
                            + "banners) and is reported for visibility only.")),
            Map.entry("EXPOSURE_GIT_CONFIG", new RuleMeta(Severity.CRITICAL,
                    "Exposed .git/config",
                    "The .git/config file is publicly readable, often enabling full source repository reconstruction.")),
            Map.entry("EXPOSURE_ENV_FILE", new RuleMeta(Severity.CRITICAL,
                    "Exposed .env file",
                    "A publicly readable .env file was found, commonly containing credentials or application secrets.")),
            Map.entry("EXPOSURE_AWS_CREDENTIALS", new RuleMeta(Severity.CRITICAL,
                    "Exposed AWS credentials file",
                    "A publicly readable .aws/credentials file was found, disclosing AWS access keys.")),
            Map.entry("EXPOSURE_SWAGGER_UI", new RuleMeta(Severity.MEDIUM,
                    "Unauthenticated API schema exposed",
                    "A Swagger/OpenAPI schema document is publicly reachable without authentication.")),
            Map.entry("EXPOSURE_GRAPHQL_INTROSPECTION", new RuleMeta(Severity.HIGH,
                    "GraphQL introspection enabled",
                    "The GraphQL endpoint accepts introspection queries without authentication, disclosing the full schema.")),
            Map.entry("EXPOSURE_PHPMYADMIN", new RuleMeta(Severity.HIGH,
                    "phpMyAdmin console exposed",
                    "A phpMyAdmin login console is publicly reachable.")),
            Map.entry("EXPOSURE_JENKINS_SCRIPT", new RuleMeta(Severity.CRITICAL,
                    "Jenkins script console exposed",
                    "The Jenkins Groovy script console is publicly reachable, allowing arbitrary code execution.")),
            Map.entry("EXPOSURE_KIBANA_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Kibana console exposed without authentication",
                    "A Kibana dashboard is publicly reachable without authentication.")),
            Map.entry("EXPOSURE_SECURITY_TXT_PRESENT", new RuleMeta(Severity.INFO,
                    "security.txt published",
                    "A /.well-known/security.txt file was found - a positive security-maturity signal.")),
            Map.entry("EXPOSURE_DOCKER_API", new RuleMeta(Severity.CRITICAL,
                    "Docker Engine API exposed without authentication",
                    "The Docker Engine remote API is reachable without TLS/authentication - equivalent to root access.")),
            Map.entry("EXPOSURE_ELASTICSEARCH_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Elasticsearch exposed without authentication",
                    "An Elasticsearch HTTP API is reachable without authentication, allowing full access to indexed data.")),
            Map.entry("EXPOSURE_REDIS_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Redis exposed without authentication",
                    "A Redis instance answered INFO without authentication, allowing full read/write access to stored data.")),
            Map.entry("EXPOSURE_CONSUL_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Consul API exposed without authentication",
                    "The Consul HTTP API is reachable without authentication.")),
            Map.entry("EXPOSURE_LIVE_SECRET_DETECTED", new RuleMeta(Severity.CRITICAL,
                    "Live-looking secret found in exposed file",
                    "The contents of an already-exposed file (.env, .git/config, or AWS credentials) contain one "
                            + "or more strings matching known live-credential formats, confirming the exposed file "
                            + "carries working-looking secrets, not just configuration structure.")));
}
