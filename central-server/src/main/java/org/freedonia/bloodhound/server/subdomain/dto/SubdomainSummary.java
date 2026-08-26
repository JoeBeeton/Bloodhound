package org.freedonia.bloodhound.server.subdomain.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.subdomain.Subdomain;

public record SubdomainSummary(
        UUID id,
        String hostname,
        Instant firstSeenAt,
        Instant lastSeenAt,
        String source,
        boolean isActive,
        List<String> currentIpAddresses) {

    public static SubdomainSummary from(Subdomain s) {
        return new SubdomainSummary(
                s.id(), s.hostname(), s.firstSeenAt(), s.lastSeenAt(), s.source(), s.isActive(), s.currentIpAddresses());
    }
}
