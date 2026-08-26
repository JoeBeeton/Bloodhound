package org.freedonia.bloodhound.server.typosquat;

import java.time.Instant;
import java.util.UUID;

public record TyposquatCandidate(
        UUID id,
        UUID targetId,
        String candidateDomain,
        String permutationType,
        Instant firstSeenAt,
        Instant lastCheckedAt,
        boolean isRegistered,
        String resolvedIp,
        Instant registrationDate) {}
