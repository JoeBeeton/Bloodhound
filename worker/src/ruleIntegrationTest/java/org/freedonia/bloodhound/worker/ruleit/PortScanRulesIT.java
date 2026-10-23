package org.freedonia.bloodhound.worker.ruleit;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.portscan.LightPortScanModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/** One admin port is a finding. Five admin ports on one host become the promiscuous rule instead. */
@ExtendWith(RuleFixture.class)
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class PortScanRulesIT {

    @Test
    void oneAdminPortPlusCleartextManagement() throws Exception {
        try (PortListeners.PortSink sink = PortListeners.PortSink.open(3306, 21, 23, 22)) {
            ModuleResult result = ScanSupport.run(new LightPortScanModule(), FixtureHosts.PORTS_ONE);
            ScanSupport.assertRules(
                    result, "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "PORT_OPEN_UNENCRYPTED_MGMT", "NETWORK_SSH_PORT_REACHABLE");
            ScanSupport.assertAsset(result, "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", FixtureHosts.PORTS_ONE + ":3306");
            ScanSupport.assertAsset(result, "PORT_OPEN_UNENCRYPTED_MGMT", FixtureHosts.PORTS_ONE + ":21");
            ScanSupport.assertAsset(result, "PORT_OPEN_UNENCRYPTED_MGMT", FixtureHosts.PORTS_ONE + ":23");
            ScanSupport.assertAsset(result, "NETWORK_SSH_PORT_REACHABLE", FixtureHosts.PORTS_ONE + ":22");
            ScanSupport.assertAbsent(result, "NETWORK_PROMISCUOUS_PORT_RESPONSE");
        }
    }

    @Test
    void fiveAdminPortsSuppressThePerPortRule() throws Exception {
        try (PortListeners.PortSink sink = PortListeners.PortSink.open(3389, 3306, 5432, 27017, 6379)) {
            ModuleResult result = ScanSupport.run(new LightPortScanModule(), FixtureHosts.PORTS_MANY);
            ScanSupport.assertRules(result, "NETWORK_PROMISCUOUS_PORT_RESPONSE");
            ScanSupport.assertAbsent(result, "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "PORT_OPEN_UNENCRYPTED_MGMT");
        }
    }
}
