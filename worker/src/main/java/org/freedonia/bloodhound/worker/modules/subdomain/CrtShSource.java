package org.freedonia.bloodhound.worker.modules.subdomain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.TreeSet;
import org.springframework.stereotype.Component;

/**
 * Subdomain discovery via crt.sh's certificate-transparency search - a plain
 * GET against a public API, no different in kind from a browser querying it,
 * squarely a Tier 1 passive technique. crt.sh can be slow (large domains,
 * shared infra) and occasionally rate-limits; this module doesn't need to be
 * fast since it runs as a background job, but a non-2xx/empty/malformed
 * response is treated as a hard failure (not "zero subdomains found") so the
 * job retries via the normal max_attempts path rather than silently reporting
 * an empty result as if it were ground truth.
 */
@Component
public class CrtShSource implements SubdomainSource {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public List<String> discover(String rootDomain) throws IOException, InterruptedException {
        String json = fetch(rootDomain);
        return parse(rootDomain, json);
    }

    @Override
    public String sourceName() {
        return "CRTSH";
    }

    String fetch(String rootDomain) throws IOException, InterruptedException {
        // "%25." decodes to a literal "%." - crt.sh's wildcard-subdomain syntax.
        URI uri = URI.create("https://crt.sh/?q=%25." + rootDomain + "&output=json");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("User-Agent", "Bloodhound-ASM/1.0 (+passive surface scan)")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("crt.sh returned HTTP " + response.statusCode() + " for " + rootDomain);
        }
        return response.body();
    }

    /**
     * Pure parse: crt.sh's name_value field can hold several
     * newline-separated hostnames per certificate (one per SAN entry), and
     * regularly includes wildcards and duplicates across rows. Lowercased,
     * wildcard-stripped, deduped, and filtered to genuine subdomains of
     * rootDomain (defensive - crt.sh occasionally returns loosely-matched
     * noise). The apex domain itself is excluded: it's already the tracked
     * target, not a discovered subdomain.
     */
    static List<String> parse(String rootDomain, String json) throws IOException {
        String root = rootDomain.toLowerCase();
        if (json == null || json.isBlank()) {
            throw new IOException("empty crt.sh response for " + rootDomain);
        }
        JsonNode arr;
        try {
            arr = OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IOException("malformed crt.sh JSON for " + rootDomain, e);
        }
        if (!arr.isArray()) {
            throw new IOException("unexpected crt.sh response shape for " + rootDomain);
        }

        TreeSet<String> hostnames = new TreeSet<>();
        for (JsonNode entry : arr) {
            JsonNode nameValue = entry.get("name_value");
            if (nameValue == null || nameValue.isNull()) {
                continue;
            }
            for (String line : nameValue.asText().split("\\n")) {
                String hostname = line.trim().toLowerCase();
                if (hostname.startsWith("*.")) {
                    hostname = hostname.substring(2);
                }
                if (hostname.isEmpty() || hostname.equals(root)) {
                    continue;
                }
                if (hostname.endsWith("." + root)) {
                    hostnames.add(hostname);
                }
            }
        }
        return List.copyOf(hostnames);
    }
}
