package org.freedonia.bloodhound.server.vuln;

import java.util.List;
import java.util.UUID;

/** One (target, hostname) currently fingerprinted with a (technology, version) pair that has a real CVE/KEV match in the cache - the direct input to finding synthesis. */
public record MatchedFingerprint(
        UUID targetId,
        String hostname,
        String technologyName,
        String version,
        List<String> cveIds,
        List<String> kevMatches,
        String maxSeverity) {}
