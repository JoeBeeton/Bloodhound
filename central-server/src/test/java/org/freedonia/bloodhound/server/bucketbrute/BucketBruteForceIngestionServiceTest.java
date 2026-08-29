package org.freedonia.bloodhound.server.bucketbrute;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class BucketBruteForceIngestionServiceTest {

    private final BucketBruteForceCheckRepository repository = mock(BucketBruteForceCheckRepository.class);
    private final BucketBruteForceCursorRepository cursorRepository = mock(BucketBruteForceCursorRepository.class);
    private final BucketBruteForceIngestionService service =
            new BucketBruteForceIngestionService(repository, cursorRepository);
    private final UUID targetId = UUID.randomUUID();

    @Test
    void checkedCandidates_upsertedOnePerEntry() {
        Map<String, Object> rawMetadata = Map.of(
                "checkedCandidates",
                List.of(
                        Map.of("candidateName", "acme-backup", "provider", "AWS_S3", "wasListable", true),
                        Map.of("candidateName", "acme-prod", "provider", "GCS", "wasListable", false)));

        service.ingest(targetId, rawMetadata);

        verify(repository).upsert(targetId, "acme-backup", "AWS_S3", true);
        verify(repository).upsert(targetId, "acme-prod", "GCS", false);
    }

    @Test
    void entryMissingCandidateNameOrProvider_skipped_notUpserted() {
        Map<String, Object> rawMetadata = Map.of(
                "checkedCandidates",
                List.of(Map.of("provider", "AWS_S3", "wasListable", true), Map.of("candidateName", "acme-x")));

        service.ingest(targetId, rawMetadata);

        verify(repository, never()).upsert(eq(targetId), eq("acme-x"), eq((String) null), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void nextLargeWordlistOffset_present_advancesCursor() {
        Map<String, Object> rawMetadata = Map.of("checkedCandidates", List.of(), "nextLargeWordlistOffset", 4500);

        service.ingest(targetId, rawMetadata);

        verify(cursorRepository).advance(targetId, 4500);
    }

    @Test
    void nextLargeWordlistOffset_absent_cursorNotTouched() {
        Map<String, Object> rawMetadata = Map.of("checkedCandidates", List.of());

        service.ingest(targetId, rawMetadata);

        verify(cursorRepository, never()).advance(eq(targetId), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    void nullRawMetadata_noInteractionsWithEitherRepository() {
        service.ingest(targetId, null);

        verify(repository, never()).upsert(eq(targetId), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyBoolean());
        verify(cursorRepository, never()).advance(eq(targetId), org.mockito.ArgumentMatchers.anyInt());
    }
}
