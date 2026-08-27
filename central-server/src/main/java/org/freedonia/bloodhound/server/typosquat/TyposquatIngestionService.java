package org.freedonia.bloodhound.server.typosquat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The TYPOSQUAT_MONITOR-specific branch in result ingestion, mirroring
 * FingerprintIngestionService: the worker's TyposquatMonitorModule is
 * entirely stateless (permutation generation, DNS resolution, and an
 * optional WHOIS lookup - no database access), so it hands back the full
 * checked-candidate list via rawMetadata rather than needing this service to
 * synthesize anything - TYPOSQUAT_DOMAIN_REGISTERED findings already arrive
 * via the normal reported-findings list, since "is this candidate
 * registered" is knowable within one scan alone, unlike SUBDOMAIN_ENUM's
 * "is this hostname new" which needs this target's history. This service's
 * only job is persisting the candidate list into typosquat_candidates.
 */
@Service
public class TyposquatIngestionService {

    private final TyposquatCandidateRepository repository;

    public TyposquatIngestionService(TyposquatCandidateRepository repository) {
        this.repository = repository;
    }

    public void ingest(UUID targetId, Map<String, Object> rawMetadata) {
        for (Map<String, Object> entry : extractCandidateList(rawMetadata)) {
            String domain = stringOrNull(entry.get("domain"));
            if (domain == null || domain.isBlank()) {
                continue;
            }
            String permutationType = stringOrNull(entry.get("permutationType"));
            boolean isRegistered = Boolean.TRUE.equals(entry.get("isRegistered"));
            String resolvedIp = stringOrNull(entry.get("resolvedIp"));
            Instant registrationDate = instantOrNull(entry.get("registrationDate"));
            byte[] screenshotPng = decodeBase64OrNull(entry.get("screenshotBase64"));
            Integer visualSimilarityPercent = intOrNull(entry.get("visualSimilarityPercent"));
            repository.upsert(
                    targetId,
                    domain,
                    permutationType == null ? "UNKNOWN" : permutationType,
                    isRegistered,
                    resolvedIp,
                    registrationDate,
                    screenshotPng,
                    visualSimilarityPercent);
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractCandidateList(Map<String, Object> rawMetadata) {
        if (rawMetadata == null) {
            return List.of();
        }
        Object raw = rawMetadata.get("candidates");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                result.add((Map<String, Object>) map);
            }
        }
        return result;
    }

    private static String stringOrNull(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static Instant instantOrNull(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(String.valueOf(value));
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] decodeBase64OrNull(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(String.valueOf(value));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Accepts a {@link Number} directly (the common case - Jackson deserializes a bare JSON
     * integer like 92 into an Integer/Long when the target type is Object) rather than
     * round-tripping through a String, which would silently lose the value for any numeric
     * type Jackson happens to represent with a fractional Java type (e.g. Double 92.0 ->
     * "92.0" -> Integer.valueOf throws).
     */
    private static Integer intOrNull(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        return null;
    }
}
