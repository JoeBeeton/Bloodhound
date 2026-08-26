package org.freedonia.bloodhound.server.orgs;

import java.time.Instant;
import java.util.UUID;

public record Organization(UUID id, String name, String slug, Instant createdAt) {}
