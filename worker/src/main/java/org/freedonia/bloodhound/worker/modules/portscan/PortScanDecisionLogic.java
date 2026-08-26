package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of an open-port list into findings - no process/XML work here, fully unit-testable. */
public final class PortScanDecisionLogic {

    static final Set<Integer> ADMIN_DB_PORTS = Set.of(3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984);
    static final Set<Integer> UNENCRYPTED_MGMT_PORTS = Set.of(21, 23);

    private PortScanDecisionLogic() {}

    /**
     * {@code openPortsByFamily} maps an address family label ("IPv4"/"IPv6")
     * to the ports found open when scanning that family's address - see
     * {@link TcpConnectPortScanner#scan}, which scans one address per family
     * a dual-stack host has. A port open on both families still produces a
     * single finding (same {@code hostname:port} dedup key as before this
     * method took family into account), but its evidence now records every
     * family it was actually reached over - e.g. an admin port exposed only
     * via IPv6 shows {@code addressFamilies: ["IPv6"]}, the exact
     * previously-invisible-to-this-scanner case this exists to surface.
     */
    public static List<RawFinding> decide(String hostname, Map<String, List<Integer>> openPortsByFamily) {
        Map<Integer, List<String>> familiesByPort = new TreeMap<>();
        openPortsByFamily.forEach((family, ports) -> {
            for (Integer port : ports) {
                familiesByPort.computeIfAbsent(port, p -> new ArrayList<>()).add(family);
            }
        });

        List<RawFinding> findings = new ArrayList<>();
        for (Map.Entry<Integer, List<String>> entry : familiesByPort.entrySet()) {
            int port = entry.getKey();
            // Sorted for deterministic evidence: openPortsByFamily is frequently a
            // Map.of(...) at call sites (TcpConnectPortScanner via LinkedHashMap is fine,
            // but tests and any future caller aren't guaranteed to be), whose iteration
            // order is unspecified - without sorting, the SAME input data could produce
            // ["IPv4","IPv6"] or ["IPv6","IPv4"] on different runs.
            List<String> addressFamilies = entry.getValue().stream().sorted().toList();
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("port", port);
            evidence.put("addressFamilies", addressFamilies);

            if (ADMIN_DB_PORTS.contains(port)) {
                findings.add(new RawFinding(
                        "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                        Severity.HIGH,
                        Category.NETWORK,
                        "Administrative/database service reachable from the internet",
                        "A port commonly used by a database or remote-administration service was found open and reachable.",
                        hostname + ":" + port,
                        evidence));
            } else if (UNENCRYPTED_MGMT_PORTS.contains(port)) {
                findings.add(new RawFinding(
                        "PORT_OPEN_UNENCRYPTED_MGMT",
                        Severity.MEDIUM,
                        Category.NETWORK,
                        "Unencrypted management protocol reachable",
                        "A port used by a plaintext management protocol (FTP or Telnet) was found open.",
                        hostname + ":" + port,
                        evidence));
            }
        }
        return findings;
    }
}
