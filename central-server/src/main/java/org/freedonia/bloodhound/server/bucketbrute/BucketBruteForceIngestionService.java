package org.freedonia.bloodhound.server.bucketbrute;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The BUCKET_BRUTE_FORCE-specific branch in result ingestion, mirroring
 * TyposquatIngestionService: the worker's BucketBruteForceModule is entirely
 * stateless (candidate generation + HTTP checks, no database access), so it
 * hands back every (candidateName, provider, wasListable) tuple it actually
 * checked this run via rawMetadata rather than needing this service to
 * synthesize anything. EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC
 * findings already arrive via the normal reported-findings list (knowable
 * within one scan), same precedent as TYPOSQUAT_DOMAIN_REGISTERED. This
 * service's only job is persisting the checked list into
 * bucket_brute_force_checks, which is what lets the *next* deep scan's job
 * payload exclude names already tried recently (see ScanRunService).
 */
@Service
public class BucketBruteForceIngestionService {

    private final BucketBruteForceCheckRepository repository;

    public BucketBruteForceIngestionService(BucketBruteForceCheckRepository repository) {
        this.repository = repository;
    }

    public void ingest(UUID targetId, Map<String, Object> rawMetadata) {
        for (Map<String, Object> entry : extractCheckedList(rawMetadata)) {
            String candidateName = stringOrNull(entry.get("candidateName"));
            String provider = stringOrNull(entry.get("provider"));
            if (candidateName == null || candidateName.isBlank() || provider == null || provider.isBlank()) {
                continue;
            }
            boolean wasListable = Boolean.TRUE.equals(entry.get("wasListable"));
            repository.upsert(targetId, candidateName, provider, wasListable);
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractCheckedList(Map<String, Object> rawMetadata) {
        if (rawMetadata == null) {
            return List.of();
        }
        Object raw = rawMetadata.get("checkedCandidates");
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
}
