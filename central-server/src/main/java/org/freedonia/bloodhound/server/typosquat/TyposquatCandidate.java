package org.freedonia.bloodhound.server.typosquat;

import java.time.Instant;
import java.util.UUID;

/**
 * {@code hasScreenshot} - never the raw image bytes themselves, which would bloat every list
 * query for a column almost nothing in that context needs. The actual bytes are fetched
 * separately and only on demand, see {@link TyposquatCandidateRepository#findScreenshotPng}.
 */
public record TyposquatCandidate(
        UUID id,
        UUID targetId,
        String candidateDomain,
        String permutationType,
        Instant firstSeenAt,
        Instant lastCheckedAt,
        boolean isRegistered,
        String resolvedIp,
        Instant registrationDate,
        boolean hasScreenshot,
        Integer visualSimilarityPercent) {}
