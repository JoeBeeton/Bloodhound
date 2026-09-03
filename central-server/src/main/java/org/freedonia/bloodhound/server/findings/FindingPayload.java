package org.freedonia.bloodhound.server.findings;

import jakarta.validation.constraints.Size;
import java.util.Map;

/**
 * Wire shape of a single finding reported by a worker in a job result.
 * Independently mirrors worker's own FindingPayload - the two are two copies
 * of one contract, not a shared type, matching how ClaimedJob/ClaimedJobDto
 * already do this across the module boundary.
 *
 * <p>A security review found no length/size bound anywhere on this record - see
 * JobResultRequest's own javadoc for the full reasoning. Bounds mirror this app's existing
 * free-text caps (target notes, attestation text: 2000 chars) rather than inventing new ones.
 */
public record FindingPayload(
        @Size(max = 200) String ruleId,
        @Size(max = 50) String severity,
        @Size(max = 100) String category,
        @Size(max = 500) String title,
        @Size(max = 4000) String description,
        @Size(max = 500) String affectedAsset,
        @Size(max = 200) Map<String, Object> evidence) {}
