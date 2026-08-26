package org.freedonia.bloodhound.common.scanmodule;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;

public record ModuleResult(
        List<RawFinding> findings,
        Map<String, Object> rawMetadata
) {
}
