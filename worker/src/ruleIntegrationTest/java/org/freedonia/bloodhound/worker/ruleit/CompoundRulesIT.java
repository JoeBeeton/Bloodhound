package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.server.compound.CompoundMatch;
import org.freedonia.bloodhound.server.compound.CompoundRiskEngine;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.worker.modules.exposure.ExposedPathModule;
import org.freedonia.bloodhound.worker.modules.tls.TlsAnalysisModule;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Feeds CompoundRiskEngine the findings the exposure and TLS modules actually emitted.
 * Patterns whose triggers land on different assets stay absent.
 */
@ExtendWith(RuleFixture.class)
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class CompoundRulesIT {

    @BeforeAll
    static void openAltPorts() throws Exception {
        RuleFixture.ensureStarted();
        PortListeners.startExposurePorts();
    }

    @AfterAll
    static void closeAltPorts() {
        PortListeners.stopExposurePorts();
    }

    @Test
    void sourcePlusEnvAndAdminConsoleWithoutHsts() throws Exception {
        ModuleResult exposure = ScanSupport.run(new ExposedPathModule(), FixtureHosts.EXPOSURE);
        ModuleResult tls = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.EXPOSURE);
        ScanSupport.assertRules(exposure, "EXPOSURE_GIT_CONFIG", "EXPOSURE_ENV_FILE", "EXPOSURE_JENKINS_SCRIPT");
        ScanSupport.assertRules(tls, "TLS_NO_HSTS");

        List<Finding> open = new ArrayList<>();
        UUID target = UUID.randomUUID();
        UUID scan = UUID.randomUUID();
        Instant now = Instant.now();
        for (RawFinding raw : exposure.findings()) {
            open.add(toFinding(raw, "EXPOSURE", target, scan, now));
        }
        for (RawFinding raw : tls.findings()) {
            open.add(toFinding(raw, "TLS", target, scan, now));
        }
        List<String> fired = CompoundRiskEngine.evaluate(open).stream()
                .map(CompoundMatch::pattern)
                .map(pattern -> pattern.ruleId())
                .toList();
        assertThat(fired).contains("COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE", "COMPOUND_INTERCEPTABLE_ADMIN_ACCESS");
        assertThat(fired)
                .doesNotContain(
                        "COMPOUND_CREDENTIAL_TO_DATA_PIVOT",
                        "COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION",
                        "COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE");
    }

    private static Finding toFinding(RawFinding raw, String moduleType, UUID target, UUID scan, Instant now) {
        return new Finding(
                UUID.randomUUID(),
                null,
                scan,
                target,
                moduleType,
                raw.ruleId(),
                raw.severity().name(),
                raw.category().name(),
                raw.title(),
                raw.description(),
                "{}",
                raw.affectedAsset(),
                scan,
                "OPEN",
                null,
                now,
                now);
    }
}
