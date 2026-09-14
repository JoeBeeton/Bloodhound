package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of a deep scan's detailed port list into findings - no
 * process/XML work here, fully unit-testable.
 *
 * <p>Reuses PORT_UNEXPECTED_OPEN_ADMIN_SERVICE/PORT_OPEN_UNENCRYPTED_MGMT
 * (same rule_ids as the Tier 1 {@link PortScanDecisionLogic}, same port sets)
 * so a port already flagged by a light scan and a deep scan are recognised as
 * the same finding rather than duplicated. Known limitation, documented
 * rather than silently accepted: central-server's FindingReconciler treats a
 * (target_id, rule_id, affected_asset) match as "already open, leave as-is"
 * and only touches updated_at - it does not currently overwrite evidence on
 * an existing OPEN finding. So the enriched service/version evidence below
 * is captured correctly in every RawFinding this module produces, but will
 * only actually land in the findings table the first time that specific
 * (rule, asset) pair is detected (e.g. a genuinely new open port, or one
 * that was previously resolved and has reappeared) - not as a retroactive
 * upgrade of an evidence-thin finding a prior Tier 1 light scan already
 * recorded. Widening FindingReconciler to always refresh evidence was judged
 * out of scope for this milestone (touches every module's ingestion path,
 * not just this one).
 */
public final class DeepPortScanDecisionLogic {

    private DeepPortScanDecisionLogic() {}

    /**
     * {@code openPorts} may contain two entries for the same {@code portId} -
     * one per address family, since {@code DeepPortScanModule} now runs the
     * full naabu+zgrab2 pipeline once per resolved family (see
     * {@link PortDetail#addressFamily}). Grouped by port before deciding, so
     * a port open on both families still produces one finding (same
     * {@code hostname:port} dedup key as before dual-stack support), with
     * evidence unioning every family it was actually found open on - a port
     * open on IPv6 only is exactly the previously-invisible case this exists
     * to surface. Service identification is taken from whichever family's
     * entry actually got a positive ID, if either did.
     */
    public static List<RawFinding> decide(String hostname, List<PortDetail> openPorts) {
        Map<Integer, List<PortDetail>> byPort = new TreeMap<>();
        for (PortDetail detail : openPorts) {
            byPort.computeIfAbsent(detail.portId(), p -> new ArrayList<>()).add(detail);
        }

        Set<Integer> openAdminPorts = byPort.keySet().stream()
                .filter(PortScanDecisionLogic.ADMIN_DB_PORTS::contains)
                .collect(Collectors.toSet());
        boolean promiscuous = PortScanDecisionLogic.isPromiscuousPortPattern(openAdminPorts);

        List<RawFinding> findings = new ArrayList<>();
        if (promiscuous) {
            findings.add(PortScanDecisionLogic.promiscuousPortFinding(hostname, openAdminPorts));
        }
        for (Map.Entry<Integer, List<PortDetail>> entry : byPort.entrySet()) {
            int portId = entry.getKey();
            List<PortDetail> details = entry.getValue();
            PortDetail representative = details.stream()
                    .filter(d -> d.serviceName() != null || d.serviceProduct() != null)
                    .findFirst()
                    .orElse(details.get(0));
            List<String> addressFamilies = addressFamilies(details);

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("port", portId);
            evidence.put("addressFamilies", addressFamilies);
            if (representative.serviceName() != null) {
                evidence.put("service", representative.serviceName());
            }
            if (representative.serviceProduct() != null) {
                evidence.put("product", representative.serviceProduct());
            }
            if (representative.serviceVersion() != null) {
                evidence.put("version", representative.serviceVersion());
            }

            // See PortScanDecisionLogic#isPromiscuousPortPattern's own doc: when most/all admin
            // ports answer at once, skip the misleading per-port claim in favor of the single
            // promiscuousPortFinding already added above.
            if (PortScanDecisionLogic.ADMIN_DB_PORTS.contains(portId)) {
                if (!promiscuous) {
                    findings.add(new RawFinding(
                            "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                            Severity.HIGH,
                            Category.NETWORK,
                            "Administrative/database service reachable from the internet",
                            "A port commonly used by a database or remote-administration service was found open and reachable"
                                    + " (deep scan identified it as " + representative.serviceSummary() + ").",
                            hostname + ":" + portId,
                            evidence));
                }
            } else if (PortScanDecisionLogic.UNENCRYPTED_MGMT_PORTS.contains(portId)) {
                findings.add(new RawFinding(
                        "PORT_OPEN_UNENCRYPTED_MGMT",
                        Severity.MEDIUM,
                        Category.NETWORK,
                        "Unencrypted management protocol reachable",
                        "A port used by a plaintext management protocol (FTP or Telnet) was found open"
                                + " (deep scan identified it as " + representative.serviceSummary() + ").",
                        hostname + ":" + portId,
                        evidence));
            }

            List<PortDetail> ftpAnonDetails =
                    details.stream().filter(d -> d.scriptOutputs().get("ftp-anon") != null).toList();
            if (!ftpAnonDetails.isEmpty()) {
                String ftpAnon = ftpAnonDetails.get(0).scriptOutputs().get("ftp-anon");
                findings.add(new RawFinding(
                        "NETWORK_ANONYMOUS_FTP",
                        Severity.CRITICAL,
                        Category.NETWORK,
                        "Anonymous FTP login allowed",
                        "The deep scan's anonymous-login probe confirmed the FTP service on this host accepts "
                                + "anonymous logins: " + ftpAnon,
                        hostname + ":" + portId,
                        Map.of("port", portId, "scriptOutput", ftpAnon, "addressFamilies", addressFamilies(ftpAnonDetails))));
            }
        }

        List<Integer> allOpenPortIds = new ArrayList<>(byPort.keySet());
        findings.add(new RawFinding(
                "NETWORK_FULL_PORT_SURFACE",
                Severity.INFO,
                Category.NETWORK,
                "Full-range port scan summary",
                "A full 65535-port deep scan found " + allOpenPortIds.size() + " open TCP port(s).",
                hostname,
                Map.of("openPortCount", allOpenPortIds.size(), "ports", allOpenPortIds)));

        return findings;
    }

    private static List<String> addressFamilies(List<PortDetail> details) {
        return details.stream()
                .map(PortDetail::addressFamily)
                .filter(f -> f != null)
                .distinct()
                .sorted(Comparator.naturalOrder())
                .toList();
    }
}
