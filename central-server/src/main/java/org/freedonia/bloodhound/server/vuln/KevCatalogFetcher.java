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
import org.springframework.stereotype.Component;

/**
 * CISA's Known Exploited Vulnerabilities catalog: a free, no-auth, CDN-served
 * static JSON file (~1600 entries, refreshed by CISA as new confirmed
 * active-exploitation CVEs are added). Fetch and parse are split the same way
 * every other module in this project splits network I/O from pure
 * interpretation, so parse() is unit-testable against a canned fixture with
 * zero network calls.
 */
@Component
public class KevCatalogFetcher {

    private static final String URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String fetchRaw() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(URL))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("CISA KEV feed returned HTTP " + response.statusCode());
        }
        return response.body();
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
