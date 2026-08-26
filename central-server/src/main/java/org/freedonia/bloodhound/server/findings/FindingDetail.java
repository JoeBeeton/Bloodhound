package org.freedonia.bloodhound.server.findings;

import java.time.Instant;

/**
 * A finding plus display-only metadata that isn't on the findings table itself:
 * firstSeenAt (the completion time of the scan run that first detected it) and
 * remediationAdvice (from rules_catalog, null for rule_ids with no catalog row -
 * e.g. ZAP_ALERT_* findings, which carry their own remediation text in evidence.solution
 * instead - the DTO layer falls back to that).
 */
public record FindingDetail(Finding finding, Instant firstSeenAt, String remediationAdvice) {}
