package org.freedonia.bloodhound.server.auth;

import java.time.Instant;
import java.util.UUID;

public record WorkerCredential(UUID id, String label, String apiKeyHash, Instant revokedAt) {}
