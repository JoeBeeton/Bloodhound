package org.freedonia.bloodhound.server.fingerprint;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The TECH_FINGERPRINT-specific branch in result ingestion, mirroring
 * SubdomainIngestionService/WhoisIngestionService: the worker's FingerprintModule
 * is entirely stateless (signature matching plus a passive ASN lookup, no
 * database access), so it hands back a structured per-hostname list via
 * rawMetadata rather than emitting findings, and this service is what
 * persists it.
 */
@Service
public class FingerprintIngestionService {

    private final FingerprintRepository fingerprintRepository;

    public FingerprintIngestionService(FingerprintRepository fingerprintRepository) {
        this.fingerprintRepository = fingerprintRepository;
    }

    public void ingest(UUID targetId, Map<String, Object> rawMetadata) {
        for (Map<String, Object> entry : extractFingerprintList(rawMetadata)) {
            String hostname = stringOrNull(entry.get("hostname"));
            if (hostname == null || hostname.isBlank()) {
                continue;
            }
            List<Technology> technologies = extractTechnologies(entry.get("technologies"));
            fingerprintRepository.upsert(
                    targetId,
                    hostname,
                    technologies,
                    stringOrNull(entry.get("hostingProvider")),
                    stringOrNull(entry.get("hostingAsn")),
                    stringOrNull(entry.get("hostingAsnOrg")),
                    extractStringList(entry.get("thirdPartyOrigins")));
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractStringList(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                result.add(String.valueOf(item));
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractFingerprintList(Map<String, Object> rawMetadata) {
        if (rawMetadata == null) {
            return List.of();
        }
        Object raw = rawMetadata.get("fingerprints");
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

    @SuppressWarnings("unchecked")
    private List<Technology> extractTechnologies(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<Technology> technologies = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                Object name = map.get("name");
                Object category = map.get("category");
                Object version = map.get("version");
                if (name != null) {
                    technologies.add(new Technology(
                            String.valueOf(name),
                            category == null ? "OTHER" : String.valueOf(category),
                            version == null ? null : String.valueOf(version)));
                }
            }
        }
        return technologies;
    }

    private static String stringOrNull(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
