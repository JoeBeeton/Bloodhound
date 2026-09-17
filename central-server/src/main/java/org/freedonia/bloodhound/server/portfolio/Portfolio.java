package org.freedonia.bloodhound.server.portfolio;

import java.time.Instant;
import java.util.UUID;

public record Portfolio(UUID id, UUID organizationId, String name, Instant createdAt) {}
