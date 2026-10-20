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
        // Same already-fetched response the presence check above just used, no second probe -
        // security.txt's own spec (RFC 9116) requires an Expires: field; a policy past that date
        // is a stale/possibly-abandoned disclosure channel rather than a currently-maintained one.
        ProbeResponse securityTxtResponse = r.get("EXPOSURE_SECURITY_TXT_PRESENT");
        if (matches(securityTxtResponse, baselineBody, b -> b.contains("Contact:"))) {
            java.time.Instant expires = parseSecurityTxtExpires(securityTxtResponse.body());
            if (expires != null && expires.isBefore(java.time.Instant.now())) {
                findings.add(finding(
                        "EXPOSURE_SECURITY_TXT_EXPIRED", hostname, Map.of("expires", expires.toString())));
            }
        }
        addIfMatches(findings, hostname, r, "EXPOSURE_DS_STORE", baselineBody, ExposedPathDecisionLogic::looksLikeDsStore);
        addIfMatches(findings, hostname, r, "EXPOSURE_DIRECTORY_LISTING", baselineBody, ExposedPathDecisionLogic::looksLikeDirectoryListing);
        addIfMatches(findings, hostname, r, "EXPOSURE_BACKUP_ARCHIVE", baselineBody,
                b -> looksLikeArchive(b, r.get("EXPOSURE_BACKUP_ARCHIVE")));
        addIfMatches(findings, hostname, r, "EXPOSURE_SQL_DUMP_FILE", baselineBody, ExposedPathDecisionLogic::looksLikeSqlDump);
        addIfMatches(findings, hostname, r, "EXPOSURE_PHP_INFO", baselineBody,
                b -> b.contains("phpinfo()") && b.contains("PHP Version"));
        addIfMatches(findings, hostname, r, "EXPOSURE_SSH_PRIVATE_KEY", baselineBody, ExposedPathDecisionLogic::looksLikePrivateKey);
        addIfMatches(findings, hostname, r, "EXPOSURE_PROMETHEUS_METRICS", baselineBody,
                b -> b.contains("# HELP ") && b.contains("# TYPE "));
        addIfMatches(findings, hostname, r, "EXPOSURE_SPRING_BOOT_H2_CONSOLE", baselineBody,
                b -> b.contains("H2 Console") && b.contains("Driver Class"));
        addIfMatches(findings, hostname, r, "EXPOSURE_LARAVEL_TELESCOPE", baselineBody, b -> b.contains("id=\"telescope\""));
        addIfMatches(findings, hostname, r, "EXPOSURE_ASPNET_TRACE_AXD", baselineBody,
                b -> b.contains("Application Trace") && b.contains("Requests to the Application"));
        addIfMatches(findings, hostname, r, "EXPOSURE_ASPNET_ELMAH", baselineBody, b -> b.contains("Error Log for"));
        addIfMatches(findings, hostname, r, "EXPOSURE_ADMINER", baselineBody, b -> b.contains("name=\"auth[driver]\""));

        // Not a catalog probe at all: reuses the baseline's own already-fetched response (a GET
        // to a deliberately-nonexistent path) rather than adding a new one, since the signal
        // this check needs - "does an error page leak a full debug/stack-trace view" - is exactly
        // what a 404 to a made-up path already exercises for free when debug mode is on.
        if (looksLikeLaravelDebugPage(baselineBody)) {
            findings.add(finding("EXPOSURE_LARAVEL_DEBUG_MODE", hostname, result.baseline()));
        }

        // Alt-port probes: different port/protocol than the baseline probe, so no soft-404-dupe guard applies -
        // the content signature (a specific JSON shape) is the sole, sufficient guard here.
        addAltPortIfMatches(findings, hostname + ":2375", r, "EXPOSURE_DOCKER_API", b -> b.contains("\"ApiVersion\""));
        addAltPortIfMatches(findings, hostname + ":9200", r, "EXPOSURE_ELASTICSEARCH_UNAUTH",
                b -> b.contains("\"cluster_name\"") || b.contains("you_know_for_search"));
        addAltPortIfMatches(findings, hostname + ":8500", r, "EXPOSURE_CONSUL_UNAUTH",
                b -> b.trim().matches("(?s)\"[0-9.]+:[0-9]+\""));
        // Grafana/Mongo Express/Traefik's own conventional default ports - not independently
        // live-verified against a real running instance the way some other checks in this file
        // were (see ProductSlugMapper's own analogous caveat for an example of this codebase's
        // convention for flagging that), worth confirming for real if these ever look
        // suspiciously silent in production.
        addAltPortIfMatches(findings, hostname + ":3000", r, "EXPOSURE_GRAFANA_UNAUTH",
                b -> b.contains("\"database\"") && b.contains("\"version\""));
        addAltPortIfMatches(findings, hostname + ":8081", r, "EXPOSURE_MONGO_EXPRESS_UNAUTH", b -> b.contains("Mongo Express"));
        addAltPortIfMatches(findings, hostname + ":8080", r, "EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH",
                b -> b.contains("\"backends\"") && b.contains("\"frontends\""));
        // A real Kubernetes API response to GET /api/v1/namespaces, when permitted, is
        // "kind":"NamespaceList" - a response denied for lack of auth is instead
        // "kind":"Status"/"reason":"Forbidden". Matching specifically on NamespaceList means this
        // only fires on confirmed anonymous read access to real cluster data, not merely "port
        // 6443 answers something" (which a properly-secured, mTLS-only API server would also do).
        addAltPortIfMatches(findings, hostname + ":6443", r, "EXPOSURE_KUBERNETES_API_UNAUTH",
                b -> b.contains("\"NamespaceList\""));
        // Apache mod_status's own distinctive page heading - a classic, well-known information
        // disclosure endpoint (Nikto's default checklist includes it) that discloses current
        // requests in flight, including client IPs and the URLs/query strings being processed -
        // routinely left enabled and world-reachable by default on a stock Apache install.
        addIfMatches(findings, hostname, r, "EXPOSURE_APACHE_SERVER_STATUS", baselineBody,
                b -> b.contains("Apache Server Status for"));
        // nginx's own stub_status module - a direct parallel to Apache mod_status, same classic
        // scanner checklist item, same "routinely left enabled by default" exposure. Discloses
        // less per-request detail than mod_status (no client IPs/URLs, just aggregate connection
        // and request counts), but still confirms internal infrastructure load/capacity, useful
        // DoS-targeting recon. "server accepts handled requests" is the module's own fixed,
        // unchanging label line - distinctive and stable across nginx versions.
        addIfMatches(findings, hostname, r, "EXPOSURE_NGINX_STUB_STATUS", baselineBody,
                b -> b.contains("Active connections:") && b.contains("server accepts handled requests"));

        if (isRedisPositive(result.redisResponse())) {
            findings.add(finding("EXPOSURE_REDIS_UNAUTH", hostname + ":6379", Map.of()));
        }

        // No soft-404/baseline-dupe guard needed here, same reasoning as the alt-port checks
        // above: each of these URLs is unique to the script it was derived from, and the positive
        // signature (a genuine source-map JSON shape) is specific enough on its own that a generic
        // catch-all page could only false-positive by coincidentally containing all three markers.
        for (Map.Entry<String, ProbeResponse> entry : result.sourceMapResponses().entrySet()) {
            ProbeResponse mapResponse = entry.getValue();
            if (mapResponse != null && mapResponse.status() == 200 && looksLikeSourceMap(mapResponse.body())) {
                findings.add(finding("EXPOSURE_JS_SOURCE_MAP", entry.getKey() + ".map", mapResponse));
            }
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

    /**
     * .DS_Store is macOS Finder's per-directory metadata file (folder view settings, icon
     * positions, and - the actually sensitive part - a record of every file/subfolder name
     * Finder has ever seen in that directory, including ones since deleted from the visible
     * listing) - accidentally deployed alongside real site content whenever someone drags a
     * folder onto a web server from a Mac without excluding it. Its binary format has a fixed,
     * well-documented magic signature at a fixed offset: bytes 0-3 are 0x00000001, bytes 4-7 are
     * the ASCII string "Bud1". "Bud1" alone is what's checked here (not the full 8-byte
     * signature) since the leading 0x00 bytes are exactly the kind of byte a lossy UTF-8 decode
     * could mangle depending on what precedes them - "Bud1" itself is pure ASCII (all four bytes
     * below 0x80), which UTF-8 always decodes correctly regardless of surrounding malformed
     * binary (invalid multi-byte sequences get replaced with U+FFFD, but a byte that's
     * unambiguously a plain ASCII character on its own is never treated as part of one), so the
     * signature survives this codebase's ordinary UTF-8 body decoding of what is otherwise a
     * binary file.
     */
    static boolean looksLikeDsStore(String body) {
        return body.contains("Bud1");
    }

    /**
     * "Index of /" is the shared, decades-old convention both Apache's mod_autoindex and nginx's
     * autoindex module use for their generated directory-listing pages - captured live against a
     * real nginx autoindex response (a dedicated fixture directory added to the juiceshop-proxy
     * dev target specifically to verify this against genuine output, not a guessed format):
     * {@code <title>Index of /path/</title>} and an identical {@code <h1>Index of /path/</h1>}.
     * Checking for the bare substring rather than the full tag also catches Apache's differently-
     * structured (table-based, not {@code <pre>}-based) listing pages, which use the exact same
     * title/heading phrasing. Unlike EXPOSURE_DS_STORE's single well-known path, a listing can be
     * enabled on any directory - since the real directory names on an arbitrary target can't be
     * known in advance, this probes a curated set of names commonly left with listing accidentally
     * on (backup/upload/log/asset directories), the same "can't know real paths, probe common
     * guesses" approach EXPOSURE_PHPMYADMIN and EXPOSURE_GIT_CONFIG already take for their own
     * unpredictable-location targets.
     */
    static boolean looksLikeDirectoryListing(String body) {
        return body.contains("Index of /");
    }

    /**
     * ZIP's own magic bytes ("PK\x03\x04"/"PK\x05\x06"/"PK\x07\x08") are all pure ASCII in their
     * first two bytes and only single-byte control characters after - unlike gzip's magic (0x1f
     * 0x8b), where the second byte is outside the ASCII range and gets mangled by this codebase's
     * lossy UTF-8 body decoding (same reasoning as {@link #looksLikeDsStore}'s own javadoc on why
     * "Bud1" alone is checked). So the body-prefix check only reliably covers ZIP; a gzip/tar
     * archive is instead caught via its Content-Type, which servers set correctly far more
     * consistently for a binary download than for, say, a JSON API error page.
     */
    static boolean looksLikeArchive(String body, ProbeResponse response) {
        if (body != null && body.startsWith("PK")) {
            return true;
        }
        if (response == null || response.contentType() == null) {
            return false;
        }
        String ct = response.contentType().toLowerCase(Locale.ROOT);
        return ct.contains("zip") || ct.contains("gzip") || ct.contains("x-tar") || ct.contains("x-compressed");
    }

    /** A handful of phrases that appear verbatim near the top of a real mysqldump/pg_dump output - specific enough that an unrelated page mentioning "CREATE TABLE" in passing (documentation, a blog post) won't also match every one of them. */
    static boolean looksLikeSqlDump(String body) {
        return body.contains("-- MySQL dump")
                || body.contains("-- PostgreSQL database dump")
                || body.contains("CREATE TABLE IF NOT EXISTS")
                || (body.contains("CREATE TABLE") && body.contains("INSERT INTO"));
    }

    /** PEM's own header line is the standard, format-defining marker for every private-key flavor (RSA/DSA/EC/OpenSSH/PKCS8) - a file without one, however it's named, isn't a private key in this format. */
    static boolean looksLikePrivateKey(String body) {
        return body.contains("-----BEGIN RSA PRIVATE KEY-----")
                || body.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
                || body.contains("-----BEGIN DSA PRIVATE KEY-----")
                || body.contains("-----BEGIN EC PRIVATE KEY-----")
                || body.contains("-----BEGIN PRIVATE KEY-----");
    }

    /** "mappings"/"sources"/"version":3 together are the source-map spec's own defining shape - an unrelated JSON response would need to coincidentally contain all three to false-positive. */
    static boolean looksLikeSourceMap(String body) {
        return body != null && body.contains("\"mappings\"") && body.contains("\"sources\"") && body.contains("\"version\":3");
    }

    /**
     * Two Laravel debug-page renderers exist depending on version: older releases (<=5.4) use
     * filp/whoops directly, newer ones wrap it in Ignition. Each marker pair requires two
     * independent substrings so a page merely mentioning "Whoops" or "Ignition" in passing
     * (a brand name, a blog post) can't false-positive on its own.
     */
    static boolean looksLikeLaravelDebugPage(String body) {
        if (body == null) {
            return false;
        }
        return (body.contains("Whoops!") && body.contains("whoops-container"))
                || (body.contains("Ignition") && body.contains("Illuminate\\"));
    }

    /** RFC 9116's Expires field is a single ISO-8601 datetime line; absent or unparseable means "unknown", not "expired". */
    static java.time.Instant parseSecurityTxtExpires(String body) {
        if (body == null) {
            return null;
        }
        for (String line : body.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.regionMatches(true, 0, "Expires:", 0, "Expires:".length())) {
                try {
                    return java.time.Instant.parse(trimmed.substring("Expires:".length()).trim());
                } catch (java.time.format.DateTimeParseException e) {
                    return null;
                }
            }
        }
        return null;
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
            Map.entry("EXPOSURE_DS_STORE", new RuleMeta(Severity.MEDIUM,
                    "Exposed .DS_Store file",
                    "A macOS Finder .DS_Store file is publicly readable, disclosing the names of files and "
                            + "subfolders Finder has seen in this directory - including ones no longer present in "
                            + "the live listing - useful for reconnaissance of the site's real directory structure.")),
            Map.entry("EXPOSURE_DIRECTORY_LISTING", new RuleMeta(Severity.MEDIUM,
                    "Directory listing enabled",
                    "A web server directory listing (Apache/nginx autoindex) is publicly reachable on a commonly "
                            + "exposed path, disclosing the names of every file it contains - including backups, "
                            + "logs, or uploads that were never meant to be individually discoverable.")),
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
            Map.entry("EXPOSURE_BACKUP_ARCHIVE", new RuleMeta(Severity.CRITICAL,
                    "Exposed backup archive",
                    "A publicly readable backup archive (.zip/.tar.gz) was found at a commonly-guessed path, "
                            + "potentially containing the full site source, configuration, or a database export.")),
            Map.entry("EXPOSURE_SQL_DUMP_FILE", new RuleMeta(Severity.CRITICAL,
                    "Exposed SQL database dump",
                    "A publicly readable SQL dump file was found at a commonly-guessed path, directly disclosing "
                            + "database contents.")),
            Map.entry("EXPOSURE_PHP_INFO", new RuleMeta(Severity.HIGH,
                    "phpinfo() page exposed",
                    "A publicly reachable phpinfo() page discloses detailed server configuration - loaded "
                            + "extensions, filesystem paths, and sometimes environment variables containing secrets.")),
            Map.entry("EXPOSURE_SSH_PRIVATE_KEY", new RuleMeta(Severity.CRITICAL,
                    "Exposed private key file",
                    "A publicly readable PEM-format private key (RSA/DSA/EC/OpenSSH) was found at a commonly-"
                            + "guessed path, potentially allowing SSH access or TLS impersonation.")),
            Map.entry("EXPOSURE_PROMETHEUS_METRICS", new RuleMeta(Severity.MEDIUM,
                    "Prometheus metrics endpoint exposed",
                    "An unauthenticated /metrics endpoint in Prometheus's text exposition format is publicly "
                            + "reachable, disclosing internal service names, request counts, and other operational "
                            + "telemetry useful for reconnaissance.")),
            Map.entry("EXPOSURE_JS_SOURCE_MAP", new RuleMeta(Severity.MEDIUM,
                    "JavaScript source map exposed",
                    "A publicly readable source map for one of this page's own JS bundles was found, disclosing "
                            + "the original, unminified source code - including any comments, internal file/folder "
                            + "structure, and business logic the build process would otherwise have stripped out.")),
            Map.entry("EXPOSURE_LIVE_SECRET_DETECTED", new RuleMeta(Severity.CRITICAL,
                    "Live-looking secret found in exposed file",
                    "The contents of an already-exposed file (.env, .git/config, or AWS credentials) contain one "
                            + "or more strings matching known live-credential formats, confirming the exposed file "
                            + "carries working-looking secrets, not just configuration structure.")),
            Map.entry("EXPOSURE_SPRING_BOOT_H2_CONSOLE", new RuleMeta(Severity.CRITICAL,
                    "H2 database console exposed",
                    "The H2 embedded database's web console is publicly reachable, allowing arbitrary SQL "
                            + "execution and, via H2's own JDBC ALIAS mechanism, remote code execution.")),
            Map.entry("EXPOSURE_LARAVEL_TELESCOPE", new RuleMeta(Severity.HIGH,
                    "Laravel Telescope exposed",
                    "Laravel's Telescope debugging dashboard is publicly reachable, disclosing application "
                            + "requests, queries, queued jobs, and exceptions - often including request "
                            + "parameters and session/cookie data.")),
            Map.entry("EXPOSURE_LARAVEL_DEBUG_MODE", new RuleMeta(Severity.HIGH,
                    "Laravel debug mode enabled",
                    "Laravel's APP_DEBUG is enabled in production, causing unhandled errors to render a full "
                            + "stack trace - including file paths, code context, and sometimes environment "
                            + "variables - to any visitor who triggers one.")),
            Map.entry("EXPOSURE_ASPNET_TRACE_AXD", new RuleMeta(Severity.HIGH,
                    "ASP.NET trace.axd exposed",
                    "ASP.NET's trace.axd diagnostic page is publicly reachable, disclosing recent request "
                            + "details including headers, session state, and server variables.")),
            Map.entry("EXPOSURE_ASPNET_ELMAH", new RuleMeta(Severity.HIGH,
                    "ASP.NET ELMAH error log exposed",
                    "The ELMAH error-logging endpoint is publicly reachable, disclosing application exception "
                            + "history - often including stack traces and request details.")),
            Map.entry("EXPOSURE_ADMINER", new RuleMeta(Severity.HIGH,
                    "Adminer database console exposed",
                    "An Adminer database-administration login console is publicly reachable.")),
            Map.entry("EXPOSURE_GRAFANA_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Grafana exposed without authentication",
                    "A Grafana instance's API is reachable without authentication, disclosing dashboard "
                            + "configuration and potentially connected data-source details.")),
            Map.entry("EXPOSURE_MONGO_EXPRESS_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Mongo Express exposed without authentication",
                    "A Mongo Express web console is publicly reachable without authentication, allowing full "
                            + "read/write access to the underlying MongoDB data.")),
            Map.entry("EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Traefik dashboard exposed without authentication",
                    "The Traefik reverse-proxy dashboard/API is reachable without authentication, disclosing "
                            + "internal backend routing and service topology.")),
            Map.entry("EXPOSURE_KUBERNETES_API_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Kubernetes API server allows anonymous access",
                    "The Kubernetes API server is reachable on its standard port (6443) and answers an "
                            + "authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the "
                            + "cluster's real namespace list. Anonymous read access to cluster-management data is "
                            + "often a foothold for broader cluster compromise - this is the control plane itself, "
                            + "not just an application.")),
            Map.entry("EXPOSURE_APACHE_SERVER_STATUS", new RuleMeta(Severity.MEDIUM,
                    "Apache mod_status page exposed",
                    "The Apache mod_status page (/server-status) is publicly reachable, disclosing currently "
                            + "in-flight requests - including client IP addresses and the URLs/query strings being "
                            + "processed, which can themselves carry session tokens or other sensitive parameters.")),
            Map.entry("EXPOSURE_NGINX_STUB_STATUS", new RuleMeta(Severity.MEDIUM,
                    "nginx stub_status page exposed",
                    "The nginx stub_status module is publicly reachable, disclosing aggregate connection and "
                            + "request counts for this server - internal infrastructure load/capacity information "
                            + "useful for targeting denial-of-service attacks.")),
            Map.entry("EXPOSURE_SECURITY_TXT_EXPIRED", new RuleMeta(Severity.INFO,
                    "security.txt has expired",
                    "The published /.well-known/security.txt file's Expires field is in the past, indicating "
                            + "the disclosure policy may be stale or no longer actively maintained.")));
}
