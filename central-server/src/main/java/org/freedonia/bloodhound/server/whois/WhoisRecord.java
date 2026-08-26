package org.freedonia.bloodhound.server.whois;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record WhoisRecord(
        UUID id,
        UUID targetId,
        Instant capturedAt,
        String registrar,
        Instant createdDate,
        Instant expiryDate,
        String registrantOrg,
        List<String> nameServers) {}
