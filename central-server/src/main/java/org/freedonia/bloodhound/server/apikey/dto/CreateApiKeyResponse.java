package org.freedonia.bloodhound.server.apikey.dto;

import java.time.Instant;
import java.util.UUID;

/** apiKey is the raw plaintext bearer credential - returned exactly once, at creation, never again. */
public record CreateApiKeyResponse(
        UUID id, String label, String keyPrefix, String apiKey, Instant createdAt, Instant expiresAt) {}
