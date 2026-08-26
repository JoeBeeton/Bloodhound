package org.freedonia.bloodhound.server.diff;

import java.util.List;
import org.freedonia.bloodhound.server.findings.Finding;

public record FindingDiffResult(
        List<Finding> newFindings,
        List<Finding> resolvedFindings,
        List<Finding> unchangedFindings,
        List<SeverityChange> changedSeverity) {

    public record SeverityChange(Finding before, Finding after) {}
}
