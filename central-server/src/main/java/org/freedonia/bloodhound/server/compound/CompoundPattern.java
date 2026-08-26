package org.freedonia.bloodhound.server.compound;

import java.util.List;
import java.util.function.Predicate;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * A curated dangerous co-occurrence pattern: fires only when every one of
 * {@code requiredGroups} has at least one match among a single asset's
 * currently-open primary findings, with no single Finding allowed to satisfy
 * more than one group (see CompoundRiskEngine) - this is what makes "any
 * other Critical/High finding" style groups safe to combine with a specific
 * trigger without a finding trivially matching itself.
 */
public record CompoundPattern(
        String ruleId, String severity, String titleTemplate, String descriptionTemplate, List<TriggerGroup> requiredGroups) {

    /** One named condition within a pattern; matched against a single asset's primary findings. */
    public record TriggerGroup(String label, Predicate<Finding> matches) {}
}
