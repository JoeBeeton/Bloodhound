package org.freedonia.bloodhound.worker.modules.documents;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DocumentMetadataDecisionLogicTest {

    private static final String DOC_URL = "https://example.com/files/handbook.pdf";

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    @Test
    void emptyMetadata_noFindings() {
        DocumentMetadata metadata = new DocumentMetadata(DOC_URL, null, null, null, null, null, List.of());
        assertThat(DocumentMetadataDecisionLogic.decide(metadata)).isEmpty();
    }

    @Test
    void authorOnly_infoFinding() {
        DocumentMetadata metadata = new DocumentMetadata(DOC_URL, "Jane Doe", null, null, null, null, List.of());
        List<RawFinding> findings = DocumentMetadataDecisionLogic.decide(metadata);
        assertThat(findings).hasSize(1);
        RawFinding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO");
        assertThat(finding.severity().name()).isEqualTo("INFO");
        assertThat(finding.affectedAsset()).isEqualTo(DOC_URL);
        assertThat(finding.evidence()).containsEntry("author", "Jane Doe");
        assertThat(finding.evidence()).doesNotContainKey("company");
    }

    @Test
    void leakedPath_mediumFindingAndAuthorFindingBothFire() {
        DocumentMetadata metadata = new DocumentMetadata(
                DOC_URL, "Jane Doe", null, "Microsoft Word", null, null, List.of("C:\\Users\\jdoe\\Documents\\handbook.docx"));
        List<RawFinding> findings = DocumentMetadataDecisionLogic.decide(metadata);
        assertThat(ruleIds(findings))
                .containsExactlyInAnyOrder("EXPOSURE_DOCUMENT_METADATA_PATH_LEAK", "EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO");
        RawFinding pathFinding = findings.stream()
                .filter(f -> f.ruleId().equals("EXPOSURE_DOCUMENT_METADATA_PATH_LEAK"))
                .findFirst()
                .orElseThrow();
        assertThat(pathFinding.severity().name()).isEqualTo("MEDIUM");
        assertThat(pathFinding.evidence().get("leakedPaths")).isEqualTo(List.of("C:\\Users\\jdoe\\Documents\\handbook.docx"));
    }

    @Test
    void allFieldsPresent_allIncludedInEvidence() {
        DocumentMetadata metadata =
                new DocumentMetadata(DOC_URL, "Jane Doe", "John Smith", "Microsoft Word", "Example Corp", "Jane Manager", List.of());
        RawFinding finding = DocumentMetadataDecisionLogic.decide(metadata).get(0);
        assertThat(finding.evidence())
                .containsEntry("author", "Jane Doe")
                .containsEntry("lastModifiedBy", "John Smith")
                .containsEntry("application", "Microsoft Word")
                .containsEntry("company", "Example Corp")
                .containsEntry("manager", "Jane Manager");
    }
}
