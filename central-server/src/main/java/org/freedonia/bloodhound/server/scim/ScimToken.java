package org.freedonia.bloodhound.server.scim;

import java.time.Instant;
import java.util.UUID;

public record ScimToken(UUID id, UUID organizationId, String label, String tokenHash, Instant createdAt, Instant revokedAt) {}
