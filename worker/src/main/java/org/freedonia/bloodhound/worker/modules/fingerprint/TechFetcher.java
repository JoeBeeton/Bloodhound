package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Fetch side of tech-stack fingerprinting: a single plain GET, same shape as
 * HttpHeaderFetcher, except the body is kept (needed for meta-generator tags
 * and script/link signatures) rather than discarded. Bounded by request
 * timeout only, not a byte cap - real pages this targets a passive scanner
 * against are not adversarially huge, and every other module in this project
 * uses the same timeout-based bounding rather than a custom size-limited body
 * subscriber. Redirects are followed manually via SafeHttpGet (SSRF guard:
 * see HttpHeaderFetcher's javadoc for why Redirect.NORMAL is not safe here).
 */
public class TechFetcher {

    private static final int BODY_CHAR_CAP = 300_000;
    private static final int MAX_REDIRECTS = 5;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public TechFetchResult fetch(String hostname) throws ScanModuleException {
        try {
            return toResult(get("https://" + hostname + "/"));
        } catch (Exception httpsFailure) {
            try {
                return toResult(get("http://" + hostname + "/"));
            } catch (Exception httpFailure) {
                throw new ScanModuleException("failed to reach " + hostname + " over HTTPS or HTTP", httpFailure);
            }
        }
    }

    private HttpResponse<String> get(String url) throws IOException, InterruptedException {
        return SafeHttpGet.get(
                client,
                url,
                Duration.ofSeconds(8),
                "Bloodhound-ASM/1.0 (+passive surface scan)",
                HttpResponse.BodyHandlers.ofString(),
                MAX_REDIRECTS);
    }

    private TechFetchResult toResult(HttpResponse<String> response) {
        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                headers.put(name.toLowerCase(), values.get(0));
            }
        });
        String body = response.body();
        if (body != null && body.length() > BODY_CHAR_CAP) {
            body = body.substring(0, BODY_CHAR_CAP);
        }
        return new TechFetchResult(headers, response.headers().allValues("set-cookie"), body == null ? "" : body);
    }
}
