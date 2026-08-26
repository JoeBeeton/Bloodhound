package org.freedonia.bloodhound.server.fingerprint;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record Fingerprint(
        UUID id,
        UUID targetId,
        String hostname,
        List<Technology> technologies,
        String hostingProvider,
        String hostingAsn,
        String hostingAsnOrg,
        List<String> thirdPartyOrigins,
        Instant capturedAt) {}
