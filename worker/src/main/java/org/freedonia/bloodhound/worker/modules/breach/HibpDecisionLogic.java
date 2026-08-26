package org.freedonia.bloodhound.worker.modules.breach;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Pure interpretation of Have I Been Pwned's two API responses - no network
 * calls, fully unit-testable against canned JSON/status codes.
 */
final class HibpDecisionLogic {

    record BreachDetail(String description, Instant breachDate) {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HibpDecisionLogic() {}

    /**
     * The domain-search response is a JSON object keyed by (privacy-preserving)
     * email alias, each value an array of breach names that alias appeared in
     * - see the class-level example in HibpBreachCorrelationSource. Every
     * alias's breach names are unioned into one deduplicated set, since the
     * finding this drives is domain-level, not per-alias.
     *
     * <p>403 and 404 are both treated as "no data available" rather than an
     * error - 403 is the documented response for a domain that isn't verified
     * under the calling API key's HIBP account (an expected, common state for
     * any domain the operator hasn't gone through HIBP's manual verification
     * flow for, not a failure), and 404 is handled the same way defensively
     * in case a zero-breach domain is reported that way. Any other status
     * (429 rate-limited, 5xx, ...) is a genuine failure the caller should
     * surface, not silently swallow.
     */
    static Set<String> parseDomainSearchBreachNames(int statusCode, String body) throws Exception {
        if (statusCode == 403 || statusCode == 404) {
            return Set.of();
        }
        if (statusCode != 200) {
            throw new IllegalStateException("HIBP domain search returned unexpected HTTP " + statusCode);
        }
        if (body == null || body.isBlank()) {
            return Set.of();
        }
        JsonNode root = MAPPER.readTree(body);
        Set<String> breachNames = new LinkedHashSet<>();
        root.fields().forEachRemaining(entry -> {
            for (JsonNode name : entry.getValue()) {
                if (name.isTextual()) {
                    breachNames.add(name.asText());
                }
            }
        });
        return breachNames;
    }

    /** Empty if the breach name is unknown (404) or the response can't be parsed - enrichment is best-effort, never fatal to the overall lookup. */
    static Optional<BreachDetail> parseBreachDetail(int statusCode, String body) {
        if (statusCode != 200 || body == null || body.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonNode root = MAPPER.readTree(body);
            String description = root.path("Description").asText(null);
            String breachDateText = root.path("BreachDate").asText(null);
            Instant breachDate = breachDateText == null
                    ? null
                    : LocalDate.parse(breachDateText).atStartOfDay(ZoneOffset.UTC).toInstant();
            return Optional.of(new BreachDetail(description, breachDate));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
