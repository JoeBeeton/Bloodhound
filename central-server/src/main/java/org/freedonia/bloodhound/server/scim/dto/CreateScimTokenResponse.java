package org.freedonia.bloodhound.server.scim.dto;

import java.time.Instant;
import java.util.UUID;

/** token is the raw plaintext bearer value - returned exactly once, at creation, never again. */
public record CreateScimTokenResponse(UUID id, String label, String token, Instant createdAt) {}
