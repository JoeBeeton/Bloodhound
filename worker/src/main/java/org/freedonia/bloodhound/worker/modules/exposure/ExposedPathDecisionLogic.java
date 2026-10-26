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
        // Pre-1.7 SVN's entries file: the format-version line is a bare integer, followed by a
        // "dir" marker on its own line - distinctive enough to avoid matching an arbitrary
        // numbers-containing text file.
        addIfMatches(findings, hostname, r, "EXPOSURE_SVN_ENTRIES", baselineBody,
                b -> b.trim().matches("(?s)^[0-9]+\\n.*") && b.contains("\ndir\n"));
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
        // Covers both web.config's XML <connectionStrings> element and appsettings.json's JSON
        // "ConnectionStrings" key - whichever of the two candidate paths actually answered - since
        // a connection string is the real secret-disclosure signal either format would carry.
        if (addIfMatches(findings, hostname, r, "EXPOSURE_DOTNET_CONFIG_FILE", baselineBody,
                b -> b.contains("connectionStrings") || b.contains("ConnectionStrings"))) {
            addSecretScanFinding(findings, hostname, r.get("EXPOSURE_DOTNET_CONFIG_FILE"), "web.config/appsettings.json");
        }
        addIfMatches(findings, hostname, r, "EXPOSURE_ADMINER", baselineBody, b -> b.contains("name=\"auth[driver]\""));
        // WordPress's own exact, stable fault message for a GET (rather than the POST its XML-RPC
        // handler actually expects) - unambiguous and requires no POST body to trigger.
        addIfMatches(findings, hostname, r, "EXPOSURE_WORDPRESS_XMLRPC", baselineBody,
                b -> b.contains("XML-RPC server accepts POST requests only."));
        // A real user listing is a JSON ARRAY of objects each carrying "slug" (often the real
        // login username) and "name" - a hardened install instead returns a JSON OBJECT error
        // like {"code":"rest_user_cannot_view",...}, which this trim().startsWith("[") check
        // naturally excludes without needing a full JSON parse.
        addIfMatches(findings, hostname, r, "EXPOSURE_WORDPRESS_USER_ENUMERATION", baselineBody,
                b -> b.trim().startsWith("[") && b.contains("\"slug\"") && b.contains("\"name\""));

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
        // Same real Docker API response shape as EXPOSURE_DOCKER_API above, just reached over the
        // TLS-secured port instead - a real, documented misconfiguration (--tls without
        // --tlsverify, or a server cert issued with no client-CA check) leaves this just as open.
        addAltPortIfMatches(
                findings, hostname + ":2376", r, "EXPOSURE_DOCKER_API_TLS", b -> b.contains("\"ApiVersion\""));
        addAltPortIfMatches(findings, hostname + ":9200", r, "EXPOSURE_ELASTICSEARCH_UNAUTH",
                b -> b.contains("\"cluster_name\"") || b.contains("you_know_for_search"));
        addAltPortIfMatches(findings, hostname + ":8500", r, "EXPOSURE_CONSUL_UNAUTH",
                b -> b.trim().matches("(?s)\"[0-9.]+:[0-9]+\""));
        // The real /api/v1/status/config response wraps the full scrape configuration YAML in a
        // "status":"success" envelope; a hardened install (e.g. an auth-requiring reverse proxy
        // in front) would instead return an auth challenge or error page, never this shape.
        addAltPortIfMatches(findings, hostname + ":9090", r, "EXPOSURE_PROMETHEUS_SERVER_UNAUTH",
                b -> b.contains("\"status\":\"success\"") && b.contains("scrape_configs"));
        // Solr's /admin/info/system response, when reachable, nests both a "solr_home" path and
        // a "lucene" object - a combination specific to a real Solr admin API response, not a
        // generic JSON error page. A hardened install (behind an auth-requiring reverse proxy)
        // returns a 401/403 challenge instead.
        addAltPortIfMatches(findings, hostname + ":8983", r, "EXPOSURE_SOLR_ADMIN_UNAUTH",
                b -> b.contains("\"solr_home\"") && b.contains("\"lucene\""));
        // A real unauthenticated _all_dbs response is a JSON ARRAY containing the literal
        // "_users" system database name - present on every CouchDB install, modern or old. A
        // hardened (post-2.0, admin-user-configured) instance instead returns a JSON OBJECT error
        // ({"error":"unauthorized",...}), which the array-vs-object distinction naturally excludes.
        addAltPortIfMatches(findings, hostname + ":5984", r, "EXPOSURE_COUCHDB_ADMIN_PARTY",
                b -> b.trim().startsWith("[") && b.contains("_users"));
        // A real unauthenticated Jupyter instance's /api/status is plain JSON carrying both of
        // these keys; a token/password-protected install answers 403 instead (which
        // addAltPortIfMatches' own status==200 gate already excludes regardless of body shape).
        addAltPortIfMatches(findings, hostname + ":8888", r, "EXPOSURE_JUPYTER_UNAUTH",
                b -> b.contains("\"started\"") && b.contains("\"kernels\""));
        // Same false-positive guard EXPOSURE_PHPMYADMIN already established: require the
        // distinctive page title AND a login-form-specific marker together, not just a stray
        // mention of "pgAdmin" in unrelated page text. pgAdmin's login form uses an email field
        // (not a plain username field like phpMyAdmin/Adminer), a distinctive quirk of its own.
        addAltPortIfMatches(findings, hostname + ":5050", r, "EXPOSURE_PGADMIN",
                b -> b.contains("pgAdmin 4") && b.contains("name=\"email\""));
        // A real, readable Airflow DAG list is a JSON object with a "dags" array; an
        // authentication-requiring instance answers 401/403 instead.
        addAltPortIfMatches(findings, hostname + ":8080", r, "EXPOSURE_AIRFLOW_UNAUTH",
                b -> b.contains("\"dags\""));
        // MLflow has no authentication mechanism at all - reachability of its own tracking-server
        // API, confirmed by a real "experiments" response shape, is itself the finding.
        addAltPortIfMatches(findings, hostname + ":5000", r, "EXPOSURE_MLFLOW_UNAUTH",
                b -> b.contains("\"experiments\""));
        // etcd's gRPC-gateway response envelope always nests a "header" object whose
        // "cluster_id" field is rendered as a JSON STRING (etcd's own int64-as-string encoding
        // quirk, e.g. "cluster_id":"14841639068965178418") - a combination specific enough to
        // confirm a genuine, successfully-executed KV query rather than merely "port 2379
        // answers something" (an auth-rejecting response would instead carry a gRPC error code,
        // not this envelope shape).
        addAltPortIfMatches(findings, hostname + ":2379", r, "EXPOSURE_ETCD_UNAUTH",
                b -> b.contains("\"header\"") && b.contains("\"cluster_id\""));
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
        // Jenkins's own distinctive script-console page copy, present only when the page actually
        // rendered rather than redirecting to a login form - this is unauthenticated Groovy
        // scripting, i.e. direct remote code execution on the Jenkins host.
        addAltPortIfMatches(findings, hostname + ":8080", r, "EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH",
                b -> b.contains("Type in an arbitrary Groovy script") && b.contains("name=\"script\""));
        // A real Kubernetes API response to GET /api/v1/namespaces, when permitted, is
        // "kind":"NamespaceList" - a response denied for lack of auth is instead
        // "kind":"Status"/"reason":"Forbidden". Matching specifically on NamespaceList means this
        // only fires on confirmed anonymous read access to real cluster data, not merely "port
        // 6443 answers something" (which a properly-secured, mTLS-only API server would also do).
        addAltPortIfMatches(findings, hostname + ":6443", r, "EXPOSURE_KUBERNETES_API_UNAUTH",
                b -> b.contains("\"NamespaceList\""));
        // Same NamespaceList fingerprint, same reasoning, different port/transport: `kubectl
        // proxy`'s own default port (8001, plain HTTP) rather than the apiserver's own TLS port.
        addAltPortIfMatches(findings, hostname + ":8001", r, "EXPOSURE_KUBECTL_PROXY_UNAUTH",
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

        for (Map.Entry<Integer, String> entry : result.jdwpResponses().entrySet()) {
            if (isJdwpPositive(entry.getValue())) {
                findings.add(finding("EXPOSURE_JDWP_UNAUTH", hostname + ":" + entry.getKey(), Map.of()));
            }
        }

        // A successful /api/whoami with guest:guest confirms the default credential pair is both
        // active and reachable from outside localhost - a hardened or default-modern instance
        // rejects it with 401, which addIfMatches-style status gating below treats as a negative.
        ProbeResponse rabbitMq = result.rabbitMqResponse();
        if (rabbitMq != null && rabbitMq.status() == 200 && rabbitMq.body() != null
                && rabbitMq.body().contains("\"name\":\"guest\"")) {
            findings.add(finding("EXPOSURE_RABBITMQ_DEFAULT_CREDS", hostname + ":15672", Map.of()));
        }

        if (isVncNoAuthPositive(result.vncResponse())) {
            findings.add(finding("EXPOSURE_VNC_NO_AUTH", hostname + ":5900", Map.of()));
        }

        if (isSnmpDefaultCommunityPositive(result.snmpResponse())) {
            findings.add(finding("EXPOSURE_SNMP_DEFAULT_COMMUNITY", hostname + ":161", Map.of()));
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

    /** JDWP's own handshake has no auth concept at all - an exact echo of the sent string is the only possible "yes" signal. */
    static boolean isJdwpPositive(String jdwpResponse) {
        return "JDWP-Handshake".equals(jdwpResponse);
    }

    /**
     * {@code vncResponse} is the server's 12-byte RFB version banner followed by its
     * security-type-list reply (see probeVnc). Byte 12 is the type count, byte 13 is the first
     * (and, for a positive, only) type code - value 1 is "None", meaning the server will accept a
     * connection with no authentication at all. Requiring the banner to start with "RFB " first
     * guards against misreading some unrelated service's reply on this port as a false positive.
     */
    static boolean isVncNoAuthPositive(String vncResponse) {
        return vncResponse != null
                && vncResponse.length() >= 14
                && vncResponse.startsWith("RFB ")
                && vncResponse.charAt(12) == 1
                && vncResponse.charAt(13) == 1;
    }

    /**
     * {@code snmpResponse} is the raw BER/ASN.1 bytes of whatever answered our SNMPv1 GetRequest
     * for sysDescr.0 with community "public" (see probeSnmp). A real SNMP agent's GetResponse PDU
     * is tagged 0xA2 (context-constructed tag 2) within a top-level SEQUENCE (tag 0x30) - checking
     * for 0xA2 early in the response is enough to confirm this is a genuine SNMP reply accepting
     * the "public" community, not an unrelated UDP service's unrelated datagram landing on the
     * same port by coincidence.
     */
    static boolean isSnmpDefaultCommunityPositive(String snmpResponse) {
        if (snmpResponse == null || snmpResponse.isEmpty() || snmpResponse.charAt(0) != 0x30) {
            return false;
        }
        int searchLimit = Math.min(snmpResponse.length(), 20);
        for (int i = 0; i < searchLimit; i++) {
            if (snmpResponse.charAt(i) == 0xA2) {
                return true;
            }
        }
        return false;
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
            // LOW, not HIGH: this rule only ever fires when NONE of the sensitive subpaths above
            // fired (see decide()'s !anyActuatorSubpathFired gate) - it's specifically the "just
            // the endpoint map is visible, nothing it points to actually disclosed anything"
            // case. A security review found this bundled into the same HIGH re-grade as
            // THREADDUMP/LOGGERS in V37 without that distinction: those two disclose real
            // internal state on their own, this one is a same-tier concern to the HEALTH/INFO
            // endpoints below (near-universally intentional, service/version fingerprinting and
            // an uptime oracle at most) - and its own description text already only promises
            // "lists management sub-endpoints", nothing more.
            Map.entry("EXPOSURE_ACTUATOR_INDEX", new RuleMeta(Severity.LOW,
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
            Map.entry("EXPOSURE_SVN_ENTRIES", new RuleMeta(Severity.CRITICAL,
                    "Exposed .svn/entries",
                    "A Subversion working copy's .svn/entries file is publicly readable, disclosing the full "
                            + "repository URL and revision metadata and often enabling source reconstruction, the "
                            + "same risk EXPOSURE_GIT_CONFIG covers for Git.")),
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
            Map.entry("EXPOSURE_DOCKER_API_TLS", new RuleMeta(Severity.CRITICAL,
                    "Docker Engine API exposed on its TLS port without client verification",
                    "The Docker Engine remote API is reachable on its TLS-secured port (2376), but without "
                            + "requiring a trusted client certificate - a documented misconfiguration (--tls set "
                            + "without --tlsverify, or a server cert issued with no client-CA check) that leaves "
                            + "the full API open to anyone who can complete a TLS handshake. Equivalent to root "
                            + "access on the host.")),
            Map.entry("EXPOSURE_ELASTICSEARCH_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Elasticsearch exposed without authentication",
                    "An Elasticsearch HTTP API is reachable without authentication, allowing full access to indexed data.")),
            Map.entry("EXPOSURE_SOLR_ADMIN_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Apache Solr admin API exposed without authentication",
                    "The Apache Solr admin API is reachable on its default port (8983) without authentication. "
                            + "Solr has no built-in authentication enabled by default, and its history includes "
                            + "multiple RCE-class CVEs reachable once any admin API access is available (e.g. "
                            + "CVE-2017-12629 XXE+RCE via the Config API, CVE-2019-0193 RCE via the "
                            + "DataImportHandler) - bare unauthenticated admin access is itself the meaningful "
                            + "finding, independent of any one specific CVE.")),
            Map.entry("EXPOSURE_JUPYTER_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Jupyter Notebook exposed without authentication",
                    "A Jupyter Notebook instance on its default port (8888) answered its API without requiring "
                            + "a token or password, confirmed via a real /api/status response. Jupyter's "
                            + "notebook cells execute arbitrary code - unauthenticated access is equivalent to "
                            + "direct remote code execution on the host.")),
            Map.entry("EXPOSURE_PGADMIN", new RuleMeta(Severity.HIGH,
                    "pgAdmin console exposed",
                    "A pgAdmin database-administration login console is publicly reachable.")),
            Map.entry("EXPOSURE_AIRFLOW_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Apache Airflow exposed without authentication",
                    "An Airflow webserver's REST API answered a real DAG list without authentication, "
                            + "disclosing every DAG's own Python source - which often embeds credentials or "
                            + "business logic - and, depending on the instance's role configuration, may also "
                            + "allow triggering DAG runs, i.e. arbitrary code execution on the Airflow host.")),
            Map.entry("EXPOSURE_MLFLOW_UNAUTH", new RuleMeta(Severity.HIGH,
                    "MLflow tracking server exposed without authentication",
                    "An MLflow tracking server's API on its default port (5000) is reachable, disclosing every "
                            + "experiment, run, metric, parameter, and model artifact path tracked on the "
                            + "server. MLflow has no built-in authentication mechanism at all, so reachability "
                            + "itself is the finding.")),
            Map.entry("EXPOSURE_COUCHDB_ADMIN_PARTY", new RuleMeta(Severity.CRITICAL,
                    "CouchDB reachable with no admin user configured (\"admin party\")",
                    "A CouchDB instance answered /_all_dbs without authentication, listing every database on the "
                            + "server. This is CouchDB's historical \"admin party\" mode (no admin user configured "
                            + "at all, the pre-2.0 default) - with no admin user set, read and write access to "
                            + "every database is open to anyone who connects.")),
            Map.entry("EXPOSURE_ETCD_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "etcd exposed without authentication",
                    "An etcd instance's v3 KV API is reachable on its default port (2379) without authentication, "
                            + "allowing a full read of every key in the store. etcd commonly backs Kubernetes' "
                            + "entire cluster state, including Secrets, which (absent an explicit "
                            + "encryption-at-rest configuration) are stored base64-encoded rather than truly "
                            + "encrypted - making an exposed, unauthenticated etcd close to a full cluster "
                            + "compromise, not just a data-disclosure finding.")),
            Map.entry("EXPOSURE_REDIS_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Redis exposed without authentication",
                    "A Redis instance answered INFO without authentication, allowing full read/write access to stored data.")),
            Map.entry("EXPOSURE_JDWP_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Java Debug Wire Protocol (JDWP) exposed",
                    "A JDWP debug listener is reachable on one of its conventional debug ports (5005 or 8000). "
                            + "JDWP has no authentication concept at all by protocol design - anyone who can "
                            + "connect can invoke arbitrary methods and inject arbitrary bytecode into the "
                            + "running JVM, equivalent to direct, unauthenticated remote code execution. A "
                            + "well-known public exploit module targets exactly this.")),
            Map.entry("EXPOSURE_RABBITMQ_DEFAULT_CREDS", new RuleMeta(Severity.CRITICAL,
                    "RabbitMQ management API accepts default credentials",
                    "The RabbitMQ management API on its default port (15672) accepted the well-known default "
                            + "credential pair (guest:guest), confirmed via a successful authenticated request. "
                            + "This grants full management access - viewing and manipulating queues, exchanges, "
                            + "and messages - to anyone who tries the default login.")),
            Map.entry("EXPOSURE_VNC_NO_AUTH", new RuleMeta(Severity.CRITICAL,
                    "VNC reachable with no authentication required",
                    "A VNC server on its default port (5900) offers only the \"None\" security type, confirmed "
                            + "via the RFB protocol's own handshake, meaning any connection is granted full "
                            + "remote desktop access with no password or other authentication at all.")),
            Map.entry("EXPOSURE_SNMP_DEFAULT_COMMUNITY", new RuleMeta(Severity.HIGH,
                    "SNMP accepts the default \"public\" community string",
                    "An SNMP agent answered a GetRequest for sysDescr.0 using the well-known default community "
                            + "string \"public\", confirmed via a real GetResponse reply. This discloses device "
                            + "and network configuration details and, depending on the agent's configuration, may "
                            + "also allow write access (SNMP SET) using the same or another commonly-guessed "
                            + "community string.")),
            Map.entry("EXPOSURE_CONSUL_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Consul API exposed without authentication",
                    "The Consul HTTP API is reachable without authentication.")),
            Map.entry("EXPOSURE_PROMETHEUS_SERVER_UNAUTH", new RuleMeta(Severity.HIGH,
                    "Prometheus server exposed without authentication",
                    "The Prometheus server's own query API is reachable on its default port (9090) without "
                            + "authentication, disclosing the full scrape configuration - every monitored "
                            + "service/job name across the whole fleet. This is distinct from, and broader than, "
                            + "a single application's own exposed /metrics endpoint.")),
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
            Map.entry("EXPOSURE_DOTNET_CONFIG_FILE", new RuleMeta(Severity.CRITICAL,
                    ".NET configuration file exposed",
                    "A .NET configuration file (web.config or appsettings.json) is publicly reachable and contains "
                            + "a connection string, routinely paired with database credentials, API keys, or other "
                            + "application secrets.")),
            Map.entry("EXPOSURE_ADMINER", new RuleMeta(Severity.HIGH,
                    "Adminer database console exposed",
                    "An Adminer database-administration login console is publicly reachable.")),
            Map.entry("EXPOSURE_WORDPRESS_XMLRPC", new RuleMeta(Severity.MEDIUM,
                    "WordPress xmlrpc.php enabled",
                    "WordPress's xmlrpc.php endpoint is enabled and reachable. Its system.multicall method lets an "
                            + "attacker attempt thousands of login guesses in a single HTTP request, bypassing "
                            + "simple per-request rate limiting, and its pingback.ping method can be abused as a "
                            + "server-side request forgery vector to make the site itself probe arbitrary "
                            + "internal or external URLs.")),
            Map.entry("EXPOSURE_WORDPRESS_USER_ENUMERATION", new RuleMeta(Severity.MEDIUM,
                    "WordPress user enumeration via REST API",
                    "WordPress's REST API users endpoint (/wp-json/wp/v2/users) publicly lists every registered "
                            + "account's slug - often the real login username - and display name. This directly "
                            + "feeds credential-stuffing and brute-force attacks by telling an attacker exactly "
                            + "which usernames to target.")),
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
            Map.entry("EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Jenkins script console exposed without authentication",
                    "Jenkins's Groovy script console is publicly reachable without authentication, allowing "
                            + "arbitrary Groovy code execution - equivalent to full remote code execution on the "
                            + "Jenkins host.")),
            Map.entry("EXPOSURE_KUBERNETES_API_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "Kubernetes API server allows anonymous access",
                    "The Kubernetes API server is reachable on its standard port (6443) and answers an "
                            + "authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the "
                            + "cluster's real namespace list. Anonymous read access to cluster-management data is "
                            + "often a foothold for broader cluster compromise - this is the control plane itself, "
                            + "not just an application.")),
            Map.entry("EXPOSURE_KUBECTL_PROXY_UNAUTH", new RuleMeta(Severity.CRITICAL,
                    "kubectl proxy exposed without authentication",
                    "A kubectl proxy instance is publicly reachable on its default port (8001) and answers an "
                            + "authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the "
                            + "cluster's real namespace list. kubectl proxy is meant for local development "
                            + "convenience and is normally bound to localhost - Kubernetes' own hardening "
                            + "documentation specifically warns against running it with a public bind address, "
                            + "and real-world incidents (including the 2018 Tesla cryptojacking breach) trace "
                            + "back to exactly this misconfiguration.")),
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
