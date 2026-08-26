package org.freedonia.bloodhound.server.findings;

import java.util.UUID;

/** The identity of a currently-OPEN finding, as needed by the dedup/resolution reconciliation. */
public record OpenFindingKey(UUID id, String ruleId, String affectedAsset) {

    // Space separator - ruleId/affectedAsset are hostnames/cookie-names/rule
    // constants and never expected to contain one.
    String dedupKey() {
        return ruleId + " " + affectedAsset;
    }
}
