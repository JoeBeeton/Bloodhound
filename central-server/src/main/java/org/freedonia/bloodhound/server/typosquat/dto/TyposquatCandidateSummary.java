package org.freedonia.bloodhound.server.typosquat.dto;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.typosquat.TyposquatCandidate;

public record TyposquatCandidateSummary(
        UUID id,
        String candidateDomain,
        String permutationType,
        Instant firstSeenAt,
        Instant lastCheckedAt,
        String resolvedIp,
        Instant registrationDate) {

    public static TyposquatCandidateSummary from(TyposquatCandidate c) {
        return new TyposquatCandidateSummary(
                c.id(),
                c.candidateDomain(),
                c.permutationType(),
                c.firstSeenAt(),
                c.lastCheckedAt(),
                c.resolvedIp(),
                c.registrationDate());
    }
}
