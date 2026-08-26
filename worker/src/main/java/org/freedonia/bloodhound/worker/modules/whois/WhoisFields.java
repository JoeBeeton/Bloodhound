package org.freedonia.bloodhound.worker.modules.whois;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Structured result of a WHOIS/RDAP lookup, whichever mechanism produced it. */
public record WhoisFields(
        String registrar,
        Instant createdDate,
        Instant expiryDate,
        String registrantOrg,
        List<String> nameServers,
        Map<String, Object> raw,
        boolean viaFallback) {

    static WhoisFields empty(boolean viaFallback) {
        return new WhoisFields(null, null, null, null, List.of(), Map.of(), viaFallback);
    }
}
