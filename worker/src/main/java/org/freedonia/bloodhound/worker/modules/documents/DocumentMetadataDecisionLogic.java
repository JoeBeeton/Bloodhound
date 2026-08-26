package org.freedonia.bloodhound.worker.modules.documents;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of an already-{@link DocumentMetadataParser}-parsed
 * {@link DocumentMetadata} into findings - no parsing-library or network
 * work here, fully unit-testable against plain records. The two checks are
 * independent, not mutually exclusive: a document can carry both an internal
 * path leak and plain author info, and both fire.
 */
public final class DocumentMetadataDecisionLogic {

    private DocumentMetadataDecisionLogic() {}

    public static List<RawFinding> decide(DocumentMetadata metadata) {
        List<RawFinding> findings = new ArrayList<>();

        if (!metadata.leakedPaths().isEmpty()) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("leakedPaths", metadata.leakedPaths());
            putIfPresent(evidence, "author", metadata.author());
            putIfPresent(evidence, "application", metadata.application());
            findings.add(new RawFinding(
                    "EXPOSURE_DOCUMENT_METADATA_PATH_LEAK",
                    Severity.MEDIUM,
                    Category.EXPOSURE,
                    "Internal file path disclosed in document metadata",
                    "A publicly reachable document's embedded metadata contains what looks like an internal "
                            + "filesystem path (e.g. a local username's home directory or a network share), typically "
                            + "left behind by the authoring application rather than anything visible when the "
                            + "document is opened normally.",
                    metadata.documentUrl(),
                    evidence));
        }

        if (metadata.hasAnyAuthorInfo()) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            putIfPresent(evidence, "author", metadata.author());
            putIfPresent(evidence, "lastModifiedBy", metadata.lastModifiedBy());
            putIfPresent(evidence, "application", metadata.application());
            putIfPresent(evidence, "company", metadata.company());
            putIfPresent(evidence, "manager", metadata.manager());
            findings.add(new RawFinding(
                    "EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO",
                    Severity.INFO,
                    Category.EXPOSURE,
                    "Author/editor information disclosed in document metadata",
                    "A publicly reachable document's embedded metadata discloses author, editor, or "
                            + "authoring-application information - individually low-risk, but useful for an "
                            + "attacker enumerating real employee names or internal usernames (e.g. for a "
                            + "phishing pretext or a password-spraying username list).",
                    metadata.documentUrl(),
                    evidence));
        }

        return findings;
    }

    private static void putIfPresent(Map<String, Object> evidence, String key, String value) {
        if (value != null && !value.isBlank()) {
            evidence.put(key, value);
        }
    }
}
