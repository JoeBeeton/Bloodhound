package org.freedonia.bloodhound.worker.modules.subdomain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.TreeSet;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
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

    /**
     * A security review found this was still using {@code BodyHandlers.ofString()}, which
     * buffers the ENTIRE response into memory with no size limit at all - the exact issue
     * {@link SafeHttpGet#readCappedUtf8} was introduced to fix elsewhere (TechFetcher,
     * DocumentFetcher, etc.), just missed here. crt.sh is a fixed, trusted host (not the scanned
     * target itself, so no redirect/SSRF exposure the way a target-controlled fetch would have),
     * but it's still an external service outside this app's control that's documented to return
     * very large JSON for heavily-certificated domains - a slow/misbehaving/compromised crt.sh
     * response could otherwise exhaust the shared worker JVM's heap, affecting every other org's
     * queued scans on that worker. Generous relative to TechFetcher/DocumentFetcher's own
     * 300,000-char page caps since a real large domain's certificate history is legitimately much
     * bigger than one HTML page (confirmed live: 1,075 discovered subdomains for one real target
     * in this deployment, and crt.sh returns one JSON row per certificate, not per deduped
     * hostname, so the raw response is a multiple of that).
     */
    private static final int BODY_CHAR_CAP = 5_000_000;

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
                .header("User-Agent", ScanUserAgent.VALUE)
                .GET()
                .build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() / 100 != 2) {
            response.body().close();
            throw new IOException("crt.sh returned HTTP " + response.statusCode() + " for " + rootDomain);
        }
        return SafeHttpGet.readCappedUtf8(response.body(), BODY_CHAR_CAP);
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
