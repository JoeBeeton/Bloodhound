package org.freedonia.bloodhound.server.botnet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * abuse.ch's Feodo Tracker - a free, no-API-key, CDN-served JSON feed of IP addresses currently
 * serving as command-and-control infrastructure for tracked banking-trojan/botnet malware
 * families (Dridex, Emotet, QakBot, TrickBot, ...). Same "free no-key feed" category as
 * endoflife.date/CISA KEV already used elsewhere in this codebase, closing a genuine gap found
 * comparing this product's rule catalog against commercial EASM/security-rating competitors:
 * SecurityScorecard and BitSight both have a dedicated "IP Reputation"/"Botnet Infections" risk
 * factor this product previously had no equivalent of at all.
 *
 * <p>Verified live before building: the real feed (https://feodotracker.abuse.ch/downloads/
 * ipblocklist.json) returned 5 entries at the time of writing, only 1 with {@code "status":
 * "online"} - the rest {@code "offline"} (Feodo Tracker's own historical record of a C2 that was
 * active in the past but no longer responds). Only "online" entries are kept - see {@link #parse}.
 */
@Component
public class FeodoTrackerClient {

    private static final Logger log = LoggerFactory.getLogger(FeodoTrackerClient.class);
    private static final String URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String fetchRaw() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(URL))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Feodo Tracker feed returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    /**
     * Pure - no network calls. Only {@code status: "online"} entries are kept: an "offline" entry
     * is Feodo Tracker's own record that the C2 isn't currently responding there anymore, and cloud
     * IP churn (AWS/DigitalOcean/etc. constantly reassigning addresses) means a stale "offline"
     * match against a target's current IP is far more likely to be coincidental IP reuse than a
     * real signal - see BotnetCorrelationScheduler's own finding-copy for how this caveat is
     * surfaced even for the "online" case kept here.
     */
    public List<BotnetIpEntry> parse(String json) {
        if (json == null) {
            return List.of();
        }
        List<BotnetIpEntry> entries = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode entry : root) {
                if (!"online".equals(textOrNull(entry, "status"))) {
                    continue;
                }
                String ip = textOrNull(entry, "ip_address");
                if (ip == null) {
                    continue;
                }
                entries.add(new BotnetIpEntry(ip, textOrNull(entry, "malware"), dateOrNull(entry, "first_seen")));
            }
        } catch (Exception e) {
            log.warn("Failed to parse Feodo Tracker feed, leaving the existing cache in place: {}", e.toString());
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
            // "first_seen" is "2022-06-04 21:24:53" (space-separated, no "T") - take the date part only.
            return LocalDate.parse(text.substring(0, 10));
        } catch (DateTimeParseException | IndexOutOfBoundsException e) {
            return null;
        }
    }
}
