package org.freedonia.bloodhound.server.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * CISA's Known Exploited Vulnerabilities catalog: a free, no-auth, CDN-served
 * static JSON file (~1800 entries, refreshed by CISA as new confirmed
 * active-exploitation CVEs are added), with CISA's GitHub copy as a fallback
 * source. Fetch and parse are split the same way
 * every other module in this project splits network I/O from pure
 * interpretation, so parse() is unit-testable against a canned fixture with
 * zero network calls.
 */
@Component
public class KevCatalogFetcher {

    private static final Logger log = LoggerFactory.getLogger(KevCatalogFetcher.class);

    static final String CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    /**
     * CISA's own GitHub repository for the same catalog. cisa.gov answers 403 to the prod host's
     * Hetzner address (even for its homepage), while this copy is reachable from it. Checked on
     * 2026-11-07: byte-identical to the cisa.gov file (same catalogVersion, entry count and hash).
     */
    static final String GITHUB_URL =
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";

    static final List<String> SOURCES = List.of(CISA_URL, GITHUB_URL);

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    /** Fetches one URL and returns the body of a 200 response, or throws. */
    interface Source {
        String get(String url) throws IOException, InterruptedException;
    }

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Source source;

    public KevCatalogFetcher() {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.source = url -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(TIMEOUT)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            return response.body();
        };
    }

    KevCatalogFetcher(Source source) {
        this.source = source;
    }

    /**
     * Tries each of {@link #SOURCES} in order and returns the first body that parses into at least
     * one catalog entry, so a block page served with a 200 also falls through to the next source.
     * Throws only when every source fails, naming each failure.
     */
    public String fetchRaw() throws IOException, InterruptedException {
        List<String> failures = new ArrayList<>();
        for (String url : SOURCES) {
            String host = URI.create(url).getHost();
            try {
                String body = source.get(url);
                if (!parse(body).isEmpty()) {
                    if (!failures.isEmpty()) {
                        log.info("KEV catalog fetched from fallback {} after: {}", host, String.join("; ", failures));
                    }
                    return body;
                }
                failures.add(host + ": no usable entries");
            } catch (IOException e) {
                failures.add(host + ": " + e.getMessage());
            }
        }
        throw new IOException("every KEV catalog source failed - " + String.join("; ", failures));
    }

    /** Pure - no network calls. Malformed individual entries are skipped rather than failing the whole parse. */
    public List<KevEntry> parse(String json) {
        List<KevEntry> entries = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode vulns = root.path("vulnerabilities");
            for (JsonNode v : vulns) {
                String cveId = textOrNull(v, "cveID");
                if (cveId == null) {
                    continue;
                }
                entries.add(new KevEntry(
                        cveId,
                        textOrNull(v, "vendorProject"),
                        textOrNull(v, "product"),
                        textOrNull(v, "vulnerabilityName"),
                        dateOrNull(v, "dateAdded")));
            }
        } catch (Exception e) {
            // A malformed feed shouldn't take down the correlation scheduler - just
            // yield nothing this cycle and try again next refresh.
            return List.of();
        }
        return entries;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static LocalDate dateOrNull(JsonNode node, String field) {
        String text = textOrNull(node, field);
        if (text == null) {
            return null;
        }
        try {
            return LocalDate.parse(text);
        } catch (Exception e) {
            return null;
        }
    }
}
