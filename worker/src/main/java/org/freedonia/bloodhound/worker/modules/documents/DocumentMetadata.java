package org.freedonia.bloodhound.worker.modules.documents;

import java.util.List;

/**
 * Metadata pulled from one discovered document, already parsed by {@link
 * DocumentMetadataParser} - every field is null/empty when the document
 * didn't carry it, never a placeholder string. {@code leakedPaths} is the
 * subset of the raw metadata values (see {@link
 * DocumentMetadataParser#PATH_PATTERNS}) that look like an internal
 * filesystem path rather than ordinary metadata text.
 */
public record DocumentMetadata(
        String documentUrl,
        String author,
        String lastModifiedBy,
        String application,
        String company,
        String manager,
        List<String> leakedPaths) {

    boolean hasAnyAuthorInfo() {
        return author != null || lastModifiedBy != null || application != null || company != null || manager != null;
    }
}
