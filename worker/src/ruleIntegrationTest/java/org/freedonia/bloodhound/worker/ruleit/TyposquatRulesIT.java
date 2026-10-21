package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.typosquat.TyposquatMonitorModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * brand.test's first TLD swap is brand.net, which the local resolver answers.
 * The screenshotter points at a closed port, so the live-site rule stays quiet.
 */
@ExtendWith(RuleFixture.class)
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class TyposquatRulesIT {

    @Test
    void registeredLookalikeWithMailAndNoScreenshot() throws Exception {
        ModuleResult result = ScanSupport.run(
                new TyposquatMonitorModule("http://127.0.0.1:9", ""), FixtureHosts.TYPOSQUAT_ROOT);
        ScanSupport.assertRules(result, "TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_MX_CONFIGURED");
        ScanSupport.assertAbsent(result, "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE");
        assertThat(result.findings())
                .filteredOn(finding -> "TYPOSQUAT_DOMAIN_REGISTERED".equals(finding.ruleId()))
                .extracting(RawFinding::affectedAsset)
                .containsExactly(FixtureHosts.TYPOSQUAT_CANDIDATE);
        ScanSupport.assertAsset(result, "BRAND_TYPOSQUAT_MX_CONFIGURED", FixtureHosts.TYPOSQUAT_CANDIDATE);
    }
}
