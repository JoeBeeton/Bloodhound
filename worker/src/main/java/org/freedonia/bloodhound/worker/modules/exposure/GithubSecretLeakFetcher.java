package org.freedonia.bloodhound.worker.modules.exposure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Fetch side of the GITHUB_SECRET_SEARCH check - no interpretation here (see
 * {@link GithubSecretLeakDecisionLogic}). Two external calls, both against fixed, trusted
 * third-party hosts (central-server's own internal API, and api.github.com), so unlike every
 * fetcher that talks to an attacker/scanned-target-influenced host, this deliberately does NOT
 * go through {@code SafeAddressValidator}/{@code SafeHttpGet.get} - same reasoning
 * {@code HibpFetcher}'s own javadoc gives for haveibeenpwned.com.
 *
 * <p>Step 1: ask central-server (the only thing with DB access, and the only place the
 * encrypted-at-rest token is ever decrypted - see {@code JobController}) for this target's
 * org's GitHub token. {@code enabled=false} means either no token is configured, the
 * integration is disabled, or the target itself is unknown - the module treats all three
 * identically (skip, don't fail the job), same "disabled, not a bug" convention as an unset
 * {@code HIBP_API_KEY}.
 *
 * <p>Step 2 (only if enabled): GitHub code-search for the root domain as a literal string,
 * then fetch each of the first {@link #MAX_CANDIDATES} hits' own file content via the Contents
 * API - the search endpoint itself never returns file bodies, only metadata.
 */
@Component
public class GithubSecretLeakFetcher {

    private static final Logger log = LoggerFactory.getLogger(GithubSecretLeakFetcher.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Bounded - GitHub's code-search API is rate-limited to ~10 req/min globally per token (see ScanJobRepository's own GITHUB_SECRET_SEARCH advisory-lock branch, which already keeps at most one of these jobs running at a time); fetching dozens of candidate files per search would still burn through that budget fast. */
    private static final int MAX_CANDIDATES = 10;

    private static final int MAX_SEARCH_RESPONSE_BYTES = 2_000_000;
    private static final int MAX_FILE_RESPONSE_BYTES = 1_000_000;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final RestClient centralServerClient;
    private final HttpClient githubClient = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    public GithubSecretLeakFetcher(RestClient centralServerClient) {
        this.centralServerClient = centralServerClient;
    }

    record TokenResponse(String token) {}

    public record CandidateFile(String repoFullName, String path, String htmlUrl, String body) {}

    public record FetchResult(boolean enabled, List<CandidateFile> candidateFiles) {}

    public FetchResult fetch(UUID targetId, String rootDomain) throws Exception {
        String token = fetchToken(targetId);
        if (token == null) {
            return new FetchResult(false, List.of());
        }
        String searchJson = searchCode(rootDomain, token);
        List<SearchHit> hits = parseSearchHits(searchJson);
        List<CandidateFile> files = new ArrayList<>();
        for (SearchHit hit : hits) {
            String body = fetchFileContent(hit.contentsUrl(), token);
            if (body != null) {
                files.add(new CandidateFile(hit.repoFullName(), hit.path(), hit.htmlUrl(), body));
            }
        }
        return new FetchResult(true, files);
    }

    /** 204 (no token configured/disabled/unknown target - central-server treats all three alike) comes back as a null body, not an error status, so no exception handling is needed for that case specifically - only genuine failures (central-server unreachable, etc.) land in the catch below. */
    private String fetchToken(UUID targetId) {
        try {
            TokenResponse response = centralServerClient
                    .get()
                    .uri("/api/v1/jobs/targets/{targetId}/github-secret-search-token", targetId)
                    .retrieve()
                    .body(TokenResponse.class);
            return response == null ? null : response.token();
        } catch (Exception e) {
            log.warn("failed to fetch github-secret-search token for target {}: {}", targetId, e.getMessage());
            return null;
        }
    }

    private String searchCode(String rootDomain, String token) throws Exception {
        String query = "\"" + rootDomain + "\"";
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("https://api.github.com/search/code?q=" + URLEncoder.encode(query, StandardCharsets.UTF_8)))
                .timeout(TIMEOUT)
                .header("User-Agent", ScanUserAgent.VALUE)
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", "Bearer " + token)
                .header("X-GitHub-Api-Version", "2022-11-28")
                .GET()
                .build();
        HttpResponse<InputStream> response = githubClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        String body = SafeHttpGet.readCappedUtf8(response.body(), MAX_SEARCH_RESPONSE_BYTES);
        if (response.statusCode() != 200) {
            log.warn("github code search for {} returned HTTP {}: {}", rootDomain, response.statusCode(), body);
            return "{}";
        }
        return body;
    }

    private String fetchFileContent(String contentsUrl, String token) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(contentsUrl))
                    .timeout(TIMEOUT)
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .header("Accept", "application/vnd.github+json")
                    .header("Authorization", "Bearer " + token)
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .GET()
                    .build();
            HttpResponse<InputStream> response = githubClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            String body = SafeHttpGet.readCappedUtf8(response.body(), MAX_FILE_RESPONSE_BYTES);
            if (response.statusCode() != 200) {
                return null;
            }
            return decodeBase64Content(body);
        } catch (Exception e) {
            // One candidate file's content fetch failing (rate limit, file deleted since the
            // search index was built, etc.) isn't worth failing the whole job over - the other
            // candidates are independent.
            log.debug("failed to fetch github file content from {}: {}", contentsUrl, e.getMessage());
            return null;
        }
    }

    record SearchHit(String repoFullName, String path, String htmlUrl, String contentsUrl) {}

    /** Pure, unit-testable against a real captured GitHub search response shape. */
    static List<SearchHit> parseSearchHits(String json) {
        List<SearchHit> hits = new ArrayList<>();
        try {
            JsonNode root = MAPPER.readTree(json);
            for (JsonNode item : root.path("items")) {
                if (hits.size() >= MAX_CANDIDATES) {
                    break;
                }
                String contentsUrl = item.path("url").asText(null);
                String path = item.path("path").asText(null);
                String htmlUrl = item.path("html_url").asText(null);
                String repoFullName = item.path("repository").path("full_name").asText(null);
                if (contentsUrl != null && path != null) {
                    hits.add(new SearchHit(repoFullName, path, htmlUrl, contentsUrl));
                }
            }
        } catch (Exception malformed) {
            // Empty/error response, or a shape this parser doesn't recognize - no candidates,
            // not a module failure.
        }
        return hits;
    }

    /** Pure - the Contents API wraps a file's body as base64, with embedded newlines GitHub inserts for readability that Java's decoder (unlike some languages' strict base64) handles fine via MIME mode. */
    static String decodeBase64Content(String contentsApiResponseJson) {
        try {
            JsonNode root = MAPPER.readTree(contentsApiResponseJson);
            if (!"base64".equals(root.path("encoding").asText(null))) {
                return null;
            }
            String content = root.path("content").asText(null);
            if (content == null) {
                return null;
            }
            return new String(Base64.getMimeDecoder().decode(content), StandardCharsets.UTF_8);
        } catch (Exception malformed) {
            return null;
        }
    }
}
