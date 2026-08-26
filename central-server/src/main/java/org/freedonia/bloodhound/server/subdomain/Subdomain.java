package org.freedonia.bloodhound.server.subdomain;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record Subdomain(
        UUID id,
        UUID targetId,
        String hostname,
        Instant firstSeenAt,
        Instant lastSeenAt,
        String source,
        boolean isActive,
        List<String> currentIpAddresses,
        String danglingCnameTarget) {}
