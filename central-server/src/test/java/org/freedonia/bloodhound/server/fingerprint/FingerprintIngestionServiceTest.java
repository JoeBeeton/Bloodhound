package org.freedonia.bloodhound.server.fingerprint;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class FingerprintIngestionServiceTest {

    private final FingerprintRepository repository = mock(FingerprintRepository.class);
    private final FingerprintIngestionService service = new FingerprintIngestionService(repository);
    private final UUID targetId = UUID.randomUUID();

    @Test
    void upsertsOneRowPerFingerprintEntry() {
        Map<String, Object> rawMetadata = Map.of(
                "fingerprints",
                List.of(
                        Map.of(
                                "hostname", "example.com",
                                "technologies",
                                        List.of(Map.of("name", "WordPress", "category", "CMS", "version", "6.4.2")),
                                "hostingProvider", "Hetzner Online GmbH",
                                "hostingAsn", "AS24940",
                                "hostingAsnOrg", "HETZNER-AS, DE"),
                        Map.of(
                                "hostname", "www.example.com",
                                "technologies", List.of())));

        service.ingest(targetId, rawMetadata);

        verify(repository).upsert(
                eq(targetId),
                eq("example.com"),
                eq(List.of(new Technology("WordPress", "CMS", "6.4.2"))),
                eq("Hetzner Online GmbH"),
                eq("AS24940"),
                eq("HETZNER-AS, DE"));
        verify(repository).upsert(eq(targetId), eq("www.example.com"), eq(List.of()), eq(null), eq(null), eq(null));
    }

    @Test
    void technologyWithoutVersion_ingestedWithNullVersionNotOmitted() {
        // Confirms the common case (no version signal in the raw data) round-trips cleanly
        // rather than throwing on a missing "version" key.
        Map<String, Object> rawMetadata = Map.of(
                "fingerprints",
                List.of(Map.of(
                        "hostname", "example.com",
                        "technologies", List.of(Map.of("name", "jQuery", "category", "JS_LIBRARY")))));

        service.ingest(targetId, rawMetadata);

        verify(repository)
                .upsert(
                        eq(targetId),
                        eq("example.com"),
                        eq(List.of(new Technology("jQuery", "JS_LIBRARY", null))),
                        eq(null),
                        eq(null),
                        eq(null));
    }

    @Test
    void entryWithoutHostname_isSkipped() {
        service.ingest(targetId, Map.of("fingerprints", List.of(Map.of("technologies", List.of()))));

        verify(repository, never()).upsert(any(), any(), any(), any(), any(), any());
    }

    @Test
    void nullOrEmptyRawMetadata_doesNothing() {
        service.ingest(targetId, null);
        service.ingest(targetId, Map.of());

        verify(repository, never()).upsert(any(), any(), any(), any(), any(), any());
    }
}
