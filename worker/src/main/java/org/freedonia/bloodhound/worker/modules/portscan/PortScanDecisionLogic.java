package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of an open-port list into findings - no process/XML work here, fully unit-testable. */
public final class PortScanDecisionLogic {

    static final Set<Integer> ADMIN_DB_PORTS = Set.of(3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984);
    static final Set<Integer> UNENCRYPTED_MGMT_PORTS = Set.of(21, 23);

    private PortScanDecisionLogic() {}

    public static List<RawFinding> decide(String hostname, List<Integer> openPorts) {
        List<RawFinding> findings = new ArrayList<>();
        for (Integer port : openPorts) {
            if (ADMIN_DB_PORTS.contains(port)) {
                findings.add(new RawFinding(
                        "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                        Severity.HIGH,
                        Category.NETWORK,
                        "Administrative/database service reachable from the internet",
                        "A port commonly used by a database or remote-administration service was found open and reachable.",
                        hostname + ":" + port,
                        Map.of("port", port)));
            } else if (UNENCRYPTED_MGMT_PORTS.contains(port)) {
                findings.add(new RawFinding(
                        "PORT_OPEN_UNENCRYPTED_MGMT",
                        Severity.MEDIUM,
                        Category.NETWORK,
                        "Unencrypted management protocol reachable",
                        "A port used by a plaintext management protocol (FTP or Telnet) was found open.",
                        hostname + ":" + port,
                        Map.of("port", port)));
            }
        }
        return findings;
    }
}
