package org.freedonia.bloodhound.server.findings;

import java.time.Instant;

/** A finding paired with its target's hostname plus display metadata - the shape needed once a query spans multiple targets in one org. */
public record OrgFinding(Finding finding, String targetHostname, Instant firstSeenAt, String remediationAdvice) {}
