package org.freedonia.bloodhound.server.typosquat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;

class TyposquatIngestionServiceTest {

    private final TyposquatCandidateRepository repository = mock(TyposquatCandidateRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final TyposquatIngestionService service = new TyposquatIngestionService(repository, targetRepository);
    private final UUID targetId = UUID.randomUUID();

    @Test
    void fullCandidateEntry_decodesScreenshotAndSimilarity_passesThroughToUpsert() {
        byte[] rawPng = new byte[] {1, 2, 3, 4};
        String base64 = Base64.getEncoder().encodeToString(rawPng);
        Map<String, Object> entry = Map.of(
                "domain", "exampl.com",
                "permutationType", "OMISSION",
                "isRegistered", true,
                "resolvedIp", "203.0.113.5",
                "registrationDate", "2026-01-01T00:00:00Z",
                "screenshotBase64", base64,
                "visualSimilarityPercent", 92);

        service.ingest(targetId, Map.of("candidates", List.of(entry)));

        verify(repository)
                .upsert(
                        eq(targetId),
                        eq("exampl.com"),
                        eq("OMISSION"),
                        eq(true),
                        eq("203.0.113.5"),
                        eq(Instant.parse("2026-01-01T00:00:00Z")),
                        eq(rawPng),
                        eq(92));
    }

    @Test
    void realSiteScreenshotPresent_decodedAndPersistedOntoTarget() {
        byte[] rawPng = new byte[] {9, 8, 7, 6};
        String base64 = Base64.getEncoder().encodeToString(rawPng);

        service.ingest(targetId, Map.of("candidates", List.of(), "realSiteScreenshotBase64", base64));

        verify(targetRepository).updateHomepageScreenshot(eq(targetId), eq(rawPng));
    }

    @Test
    void realSiteScreenshotAbsent_neverTouchesTargetRepository() {
        service.ingest(targetId, Map.of("candidates", List.of()));

        verifyNoInteractions(targetRepository);
    }

    @Test
    void realSiteScreenshotMalformedBase64_neverTouchesTargetRepository() {
        service.ingest(targetId, Map.of("candidates", List.of(), "realSiteScreenshotBase64", "not valid base64!!!"));

        verifyNoInteractions(targetRepository);
    }

    @Test
    void unregisteredCandidate_noScreenshotOrSimilarity_upsertedWithNulls() {
        Map<String, Object> entry = Map.of(
                "domain", "exampl.com", "permutationType", "OMISSION", "isRegistered", false);

        service.ingest(targetId, Map.of("candidates", List.of(entry)));

        verify(repository)
                .upsert(
                        eq(targetId),
                        eq("exampl.com"),
                        eq("OMISSION"),
                        eq(false),
                        isNull(),
                        isNull(),
                        isNull(),
                        isNull());
    }

    @Test
    void malformedBase64_decodesToNull_ratherThanThrowing() {
        Map<String, Object> entry = Map.of(
                "domain", "exampl.com",
                "permutationType", "OMISSION",
                "isRegistered", true,
                "screenshotBase64", "not valid base64!!!");

        service.ingest(targetId, Map.of("candidates", List.of(entry)));

        verify(repository).upsert(any(), any(), any(), eq(true), any(), any(), isNull(), any());
    }

    @Test
    void blankOrMissingDomain_skipped_neverUpserted() {
        service.ingest(
                targetId,
                Map.of(
                        "candidates",
                        List.of(Map.of("permutationType", "OMISSION"), Map.of("domain", "", "permutationType", "OMISSION"))));

        verify(repository, never()).upsert(any(), any(), any(), anyBool(), any(), any(), any(), any());
    }

    @Test
    void nullRawMetadata_noInteractionsWithEitherRepository() {
        service.ingest(targetId, null);
        verify(repository, never()).upsert(any(), any(), any(), anyBool(), any(), any(), any(), any());
        verifyNoInteractions(targetRepository);
    }

    @Test
    void missingCandidatesKey_noInteractionsWithRepository() {
        service.ingest(targetId, Map.of("generated", 42));
        verify(repository, never()).upsert(any(), any(), any(), anyBool(), any(), any(), any(), any());
    }

    private static boolean anyBool() {
        return org.mockito.ArgumentMatchers.anyBoolean();
    }
}
