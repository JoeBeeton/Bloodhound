package org.freedonia.bloodhound.common.scanmodule;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ScanContext(
        UUID targetId,
        String hostname,
        List<String> knownSubdomains,
        Map<String, Object> jobPayload
) {
}
