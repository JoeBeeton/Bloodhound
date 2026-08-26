package org.freedonia.bloodhound.common.findings;

import java.util.Map;

/**
 * A single finding as produced by a {@code ScanModule}, before it is persisted
 * and deduplicated by central-server's result-ingestion pipeline.
 *
 * @param ruleId         key into the rules_catalog, e.g. "TLS_WEAK_PROTOCOL_SUPPORTED"
 * @param affectedAsset  the specific hostname/IP/port/path this finding concerns
 * @param evidence       raw proof captured for the finding (e.g. response headers, cert details)
 */
public record RawFinding(
        String ruleId,
        Severity severity,
        Category category,
        String title,
        String description,
        String affectedAsset,
        Map<String, Object> evidence
) {
}
