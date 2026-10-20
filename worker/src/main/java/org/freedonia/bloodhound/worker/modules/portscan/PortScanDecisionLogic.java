package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of an open-port list into findings - no process/XML work here, fully unit-testable. */
public final class PortScanDecisionLogic {

    static final Set<Integer> ADMIN_DB_PORTS =
            Set.of(3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984, 135, 139, 445);
    static final Set<Integer> UNENCRYPTED_MGMT_PORTS = Set.of(21, 23);

    /**
     * SMB (445), NetBIOS Session Service (139), and the MSRPC endpoint mapper (135) - folded into
     * {@link #ADMIN_DB_PORTS} (so they share its promiscuous-port false-positive protection
     * below) but flagged under their own, more severe rule: these protocols were never designed
     * for internet exposure at all, unlike the database/remote-desktop services the rest of
     * ADMIN_DB_PORTS covers, and have a long history of wormable, pre-authentication remote code
     * execution vulnerabilities (MS17-010/EternalBlue, exploited by WannaCry and NotPetya -
     * arguably the most damaging self-propagating malware outbreaks on record, both enabled by
     * internet-facing SMB).
     */
    static final Set<Integer> SMB_NETBIOS_RPC_PORTS = Set.of(135, 139, 445);

    /**
     * Found live: two real hosts (jaja.co.uk's joinbeta/pioneers subdomains) both showed every
     * single one of {@link #ADMIN_DB_PORTS}' 9 entries open at once - RDP, MySQL, Postgres,
     * MongoDB, Redis, MSSQL, Oracle, VNC, and CouchDB, simultaneously, on the same host. No real
     * infrastructure runs all nine of those unrelated vendor protocols on one box exposed to the
     * internet; this is the signature of a firewall/load balancer/WAF accepting TCP connections
     * on every port rather than nine genuinely exposed services. Confirmed independently, live,
     * against the raw sockets themselves (not just our own scanner): a passive read from port
     * 3306 (MySQL, which unconditionally sends its handshake packet unprompted the instant a
     * real server accepts a connection) returned zero bytes after several seconds, and an
     * explicit Redis PING sent to port 6379 got no +PONG reply at all - both null results
     * regardless of the specific host or port, which real running services never produce.
     * Deliberately a simple absolute-count threshold (not, say, "ADMIN_DB_PORTS.size()", which
     * would only catch the literal all-nine case): a host that happens to expose two or three of
     * these for a real, if risky, reason is still worth its own specific per-port findings; five
     * or more distinct, unrelated database/admin protocols all answering at once is past what any
     * legitimate single host would ever combine.
     */
    static final int PROMISCUOUS_PORT_THRESHOLD = 5;

    /**
     * True when {@code openAdminPorts} (the subset of {@link #ADMIN_DB_PORTS} found open on one
     * host) is large enough that treating each one as a genuine, independently-exposed service
     * would be misleading - see {@link #PROMISCUOUS_PORT_THRESHOLD}'s own comment for the live
     * incident this exists to catch.
     */
    static boolean isPromiscuousPortPattern(Set<Integer> openAdminPorts) {
        return openAdminPorts.size() >= PROMISCUOUS_PORT_THRESHOLD;
    }

    static RawFinding promiscuousPortFinding(String hostname, Set<Integer> openAdminPorts) {
        List<Integer> sortedPorts = openAdminPorts.stream().sorted().toList();
        return new RawFinding(
                "NETWORK_PROMISCUOUS_PORT_RESPONSE",
                Severity.INFO,
                Category.NETWORK,
                "Unusually many admin/database ports appear open at once",
                sortedPorts.size() + " of " + ADMIN_DB_PORTS.size() + " commonly-flagged administrative/database "
                        + "ports (covering several unrelated vendor protocols) all appear open on this host "
                        + "simultaneously - a pattern real infrastructure essentially never produces, and much more "
                        + "consistent with a firewall, load balancer, or WAF accepting TCP connections on every "
                        + "port than with that many distinct services genuinely being exposed. Reported here "
                        + "instead of as individual per-port findings so the ambiguity is visible rather than "
                        + "implying confirmed exposure of every listed service.",
                hostname,
                Map.of("openAdminPorts", sortedPorts));
    }

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

        Set<Integer> openAdminPorts =
                familiesByPort.keySet().stream().filter(ADMIN_DB_PORTS::contains).collect(Collectors.toSet());
        boolean promiscuous = isPromiscuousPortPattern(openAdminPorts);

        List<RawFinding> findings = new ArrayList<>();
        if (promiscuous) {
            findings.add(promiscuousPortFinding(hostname, openAdminPorts));
        }
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

            // See isPromiscuousPortPattern's own doc: when most/all of ADMIN_DB_PORTS answer at
            // once, the individual per-port "this specific service is exposed" claim is more
            // likely a firewall/LB artifact than nine real findings - promiscuousPortFinding
            // above already surfaces the ambiguity as a single finding, so skip the misleading
            // per-port ones rather than reporting both.
            if (ADMIN_DB_PORTS.contains(port)) {
                if (!promiscuous && SMB_NETBIOS_RPC_PORTS.contains(port)) {
                    findings.add(new RawFinding(
                            "NETWORK_SMB_NETBIOS_EXPOSED",
                            Severity.CRITICAL,
                            Category.NETWORK,
                            "Windows file-sharing/RPC service reachable from the internet",
                            "A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) was "
                                    + "found open and reachable from the internet. These protocols were never "
                                    + "designed for internet exposure and have a long history of wormable, "
                                    + "pre-authentication remote code execution vulnerabilities (e.g. "
                                    + "MS17-010/EternalBlue, exploited by WannaCry and NotPetya) - internet-facing "
                                    + "SMB is one of the most consistently dangerous network exposures a host can have.",
                            hostname + ":" + port,
                            evidence));
                } else if (!promiscuous) {
                    findings.add(new RawFinding(
                            "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                            Severity.HIGH,
                            Category.NETWORK,
                            "Administrative/database service reachable from the internet",
                            "A port commonly used by a database or remote-administration service was found open and reachable.",
                            hostname + ":" + port,
                            evidence));
                }
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
