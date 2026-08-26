package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    public static List<RawFinding> decide(String hostname, List<PortDetail> openPorts) {
        List<RawFinding> findings = new ArrayList<>();
        for (PortDetail port : openPorts) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("port", port.portId());
            if (port.serviceName() != null) {
                evidence.put("service", port.serviceName());
            }
            if (port.serviceProduct() != null) {
                evidence.put("product", port.serviceProduct());
            }
            if (port.serviceVersion() != null) {
                evidence.put("version", port.serviceVersion());
            }

            if (PortScanDecisionLogic.ADMIN_DB_PORTS.contains(port.portId())) {
                findings.add(new RawFinding(
                        "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                        Severity.HIGH,
                        Category.NETWORK,
                        "Administrative/database service reachable from the internet",
                        "A port commonly used by a database or remote-administration service was found open and reachable"
                                + " (deep scan identified it as " + port.serviceSummary() + ").",
                        hostname + ":" + port.portId(),
                        evidence));
            } else if (PortScanDecisionLogic.UNENCRYPTED_MGMT_PORTS.contains(port.portId())) {
                findings.add(new RawFinding(
                        "PORT_OPEN_UNENCRYPTED_MGMT",
                        Severity.MEDIUM,
                        Category.NETWORK,
                        "Unencrypted management protocol reachable",
                        "A port used by a plaintext management protocol (FTP or Telnet) was found open"
                                + " (deep scan identified it as " + port.serviceSummary() + ").",
                        hostname + ":" + port.portId(),
                        evidence));
            }

            String ftpAnon = port.scriptOutputs().get("ftp-anon");
            if (ftpAnon != null) {
                findings.add(new RawFinding(
                        "NETWORK_ANONYMOUS_FTP",
                        Severity.CRITICAL,
                        Category.NETWORK,
                        "Anonymous FTP login allowed",
                        "The deep scan's anonymous-login probe confirmed the FTP service on this host accepts "
                                + "anonymous logins: " + ftpAnon,
                        hostname + ":" + port.portId(),
                        Map.of("port", port.portId(), "scriptOutput", ftpAnon)));
            }
        }

        List<Integer> allOpenPortIds = openPorts.stream().map(PortDetail::portId).toList();
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
}
