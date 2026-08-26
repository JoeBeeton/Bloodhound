package org.freedonia.bloodhound.server.fingerprint.dto;

import java.time.Instant;
import java.util.List;
import org.freedonia.bloodhound.server.fingerprint.Fingerprint;
import org.freedonia.bloodhound.server.fingerprint.Technology;

public record FingerprintSummary(
        String hostname,
        List<Technology> technologies,
        String hostingProvider,
        String hostingAsn,
        String hostingAsnOrg,
        List<String> thirdPartyOrigins,
        Instant capturedAt) {

    public static FingerprintSummary from(Fingerprint f) {
        return new FingerprintSummary(
                f.hostname(),
                f.technologies(),
                f.hostingProvider(),
                f.hostingAsn(),
                f.hostingAsnOrg(),
                f.thirdPartyOrigins(),
                f.capturedAt());
    }
}
