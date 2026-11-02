package org.freedonia.bloodhound.common.scanmodule;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * {@code jobId} is null outside a real claimed job (tests, the rule-integration harness) - only
 * modules that call back to central-server mid-job need it, to prove which job they're acting for.
 */
public record ScanContext(
        UUID targetId,
        String hostname,
        List<String> knownSubdomains,
        Map<String, Object> jobPayload,
        UUID jobId
) {
    public ScanContext(UUID targetId, String hostname, List<String> knownSubdomains, Map<String, Object> jobPayload) {
        this(targetId, hostname, knownSubdomains, jobPayload, null);
    }
}
