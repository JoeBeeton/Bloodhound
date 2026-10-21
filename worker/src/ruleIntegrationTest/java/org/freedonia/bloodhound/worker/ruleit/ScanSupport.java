package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;

final class ScanSupport {

    private ScanSupport() {}

    static ModuleResult run(ScanModule module, String hostname) throws Exception {
        return module.execute(new ScanContext(UUID.randomUUID(), hostname, List.of(), Map.of()));
    }

    static List<String> ruleIds(ModuleResult result) {
        return result.findings().stream().map(RawFinding::ruleId).toList();
    }

    static void assertRules(ModuleResult result, String... ruleIds) {
        assertThat(ruleIds(result)).contains(ruleIds);
    }

    static void assertAbsent(ModuleResult result, String... ruleIds) {
        assertThat(ruleIds(result)).doesNotContain(ruleIds);
    }

    static void assertAsset(ModuleResult result, String ruleId, String asset) {
        assertThat(result.findings())
                .filteredOn(finding -> finding.ruleId().equals(ruleId))
                .extracting(RawFinding::affectedAsset)
                .contains(asset);
    }
}
