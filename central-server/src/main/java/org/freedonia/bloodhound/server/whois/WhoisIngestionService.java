package org.freedonia.bloodhound.server.whois;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.springframework.stereotype.Service;

/**
 * The WHOIS-specific branch in result ingestion, mirroring
 * SubdomainIngestionService: the worker's WhoisModule is stateless (it can
 * compute WHOIS_EXPIRY_APPROACHING itself from the current lookup alone, so
 * that finding already arrives via the normal reported-findings list) but has
 * no visibility into this target's WHOIS history, so "did the registrar
 * change since last time" is a database-backed question answered here -
 * compare this lookup's registrar against the immediately-previous
 * whois_records row before inserting the new one.
 */
@Service
public class WhoisIngestionService {

    private final WhoisRecordRepository whoisRecordRepository;

    public WhoisIngestionService(WhoisRecordRepository whoisRecordRepository) {
        this.whoisRecordRepository = whoisRecordRepository;
    }

    public List<FindingPayload> ingestAndSynthesizeFindings(
            UUID targetId, String hostname, Map<String, Object> rawMetadata, List<FindingPayload> reportedFindings) {
        if (rawMetadata == null || rawMetadata.isEmpty()) {
            return reportedFindings;
        }

        String registrar = stringOrNull(rawMetadata.get("registrar"));
        Instant createdDate = instantOrNull(rawMetadata.get("createdDate"));
        Instant expiryDate = instantOrNull(rawMetadata.get("expiryDate"));
        String registrantOrg = stringOrNull(rawMetadata.get("registrantOrg"));
        @SuppressWarnings("unchecked")
        List<String> nameServers = rawMetadata.get("nameServers") instanceof List<?> list
                ? list.stream().map(String::valueOf).toList()
                : List.of();
        Object raw = rawMetadata.getOrDefault("raw", Map.of());

        Optional<WhoisRecord> previous = whoisRecordRepository.findLatest(targetId);
        List<FindingPayload> combined = new ArrayList<>(reportedFindings);
        if (previous.isPresent()
                && previous.get().registrar() != null
                && registrar != null
                && !Objects.equals(previous.get().registrar(), registrar)) {
            combined.add(new FindingPayload(
                    "WHOIS_REGISTRANT_CHANGED",
                    "INFO",
                    "WHOIS",
                    "Domain registrar changed",
                    "The registrar on record for this domain changed since the previous WHOIS/RDAP observation.",
                    hostname,
                    Map.of("previousRegistrar", previous.get().registrar(), "currentRegistrar", registrar)));
        }

        whoisRecordRepository.insert(targetId, registrar, createdDate, expiryDate, registrantOrg, nameServers, raw);
        return combined;
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
}
