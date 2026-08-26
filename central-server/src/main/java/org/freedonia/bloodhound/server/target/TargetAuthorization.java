package org.freedonia.bloodhound.server.target;

import java.time.Instant;
import java.util.UUID;

/** One attestation record - see target_authorizations (V3), unused until Phase 2 Milestone A. */
public record TargetAuthorization(
        UUID id,
        UUID targetId,
        UUID authorizedByUserId,
        Instant authorizedAt,
        String attestationText,
        Instant revokedAt,
        UUID revokedByUserId) {

    public boolean isRevoked() {
        return revokedAt != null;
    }
}
