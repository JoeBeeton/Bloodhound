package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.documents.DocumentMetadataModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(RuleFixture.class)
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class DocumentMetadataRulesIT {

    @Test
    void linkedPdfLeaksAHomePathAndAnAuthor() throws Exception {
        ModuleResult result = ScanSupport.run(new DocumentMetadataModule(), FixtureHosts.DOCS);
        ScanSupport.assertRules(
                result, "EXPOSURE_DOCUMENT_METADATA_PATH_LEAK", "EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO");
        assertThat(result.findings())
                .filteredOn(finding -> finding.ruleId().startsWith("EXPOSURE_DOCUMENT_METADATA_"))
                .extracting(RawFinding::affectedAsset)
                .allMatch(asset -> asset.equals("https://" + FixtureHosts.DOCS + "/files/report.pdf"));
    }
}
