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
                if (!promiscuous && PortScanDecisionLogic.SMB_NETBIOS_RPC_PORTS.contains(portId)) {
                    // Same rule_id/severity as PortScanDecisionLogic's own Tier 1 finding for
                    // this exact port when confirmed - required so central-server's (target_id,
                    // rule_id, affected_asset) dedup recognizes a port already flagged by a light
                    // scan and a deep scan as the same finding, same reasoning as this file's own
                    // class javadoc already applies to the other two rule_ids. "Confirmed" means a
                    // DeepPortScanModule-run SmbRpcConfirmationProbe actually got a valid SMB
                    // negotiate/DCE-RPC bind reply - zgrab2's own generic banner probe above never
                    // gets a positive ID for SMB/RPC (neither sends an unprompted banner), so
                    // without this a bare open port on 135/445 would still read as CRITICAL from
                    // nothing more than naabu's TCP connect, same gap PortScanDecisionLogic's own
                    // SMB_NETBIOS_RPC_PORTS doc covers for the Tier 1 light scan.
                    boolean confirmed = details.stream()
                            .anyMatch(d -> "true".equals(d.scriptOutputs().get("smb-rpc-confirmed")));
                    evidence.put("protocolConfirmed", confirmed);
                    if (confirmed) {
                        findings.add(new RawFinding(
                                "NETWORK_SMB_NETBIOS_EXPOSED",
                                Severity.CRITICAL,
                                Category.NETWORK,
                                "Windows file-sharing/RPC service reachable from the internet",
                                "A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) was "
                                        + "found open and reachable from the internet (deep scan identified it as "
                                        + representative.serviceSummary() + "), and a follow-up SMB negotiate/DCE-RPC "
                                        + "bind probe confirmed a real protocol response. These protocols were never "
                                        + "designed for internet exposure and have a long history of wormable, "
                                        + "pre-authentication remote code execution vulnerabilities (e.g. "
                                        + "MS17-010/EternalBlue, exploited by WannaCry and NotPetya).",
                                hostname + ":" + portId,
                                evidence));
                    } else {
                        findings.add(new RawFinding(
                                "NETWORK_SMB_NETBIOS_PORT_OPEN_UNCONFIRMED",
                                Severity.MEDIUM,
                                Category.NETWORK,
                                "Port used by SMB/NetBIOS/RPC accepted a connection, but the protocol itself didn't respond",
                                "A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) "
                                        + "accepted a plain TCP connection (deep scan identified it as "
                                        + representative.serviceSummary() + "), but a follow-up SMB negotiate/DCE-RPC "
                                        + "bind probe got no valid protocol reply - see NETWORK_SMB_NETBIOS_EXPOSED's "
                                        + "own notes on why that's not yet strong enough evidence for a Critical rating.",
                                hostname + ":" + portId,
                                evidence));
                    }
                } else if (!promiscuous && PortScanDecisionLogic.MEMCACHED_PORTS.contains(portId)) {
                    // Same rule_id/severity as PortScanDecisionLogic's own Tier 1 finding for
                    // this exact port - see NETWORK_SMB_NETBIOS_EXPOSED's own comment above for
                    // why.
                    findings.add(new RawFinding(
                            "NETWORK_MEMCACHED_EXPOSED",
                            Severity.CRITICAL,
                            Category.NETWORK,
                            "Memcached reachable from the internet",
                            "Memcached's default port (11211) was found open and reachable from the internet "
                                    + "(deep scan identified it as " + representative.serviceSummary() + "). "
                                    + "Memcached ships with no authentication at all by default, so a reachable "
                                    + "instance discloses whatever an application cached in it to anyone who "
                                    + "connects, and internet-exposed memcached servers were the vector behind the "
                                    + "largest DDoS amplification attacks on record.",
                            hostname + ":" + portId,
                            evidence));
                } else if (!promiscuous) {
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
            } else if (PortScanDecisionLogic.CLEARTEXT_MAIL_PORTS.contains(portId)) {
                // Same rule_id/severity as PortScanDecisionLogic's own Tier 1 finding for this
                // exact port - see NETWORK_SMB_NETBIOS_EXPOSED's own comment above for why.
                findings.add(new RawFinding(
                        "NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED",
                        Severity.MEDIUM,
                        Category.NETWORK,
                        "Cleartext mail retrieval protocol reachable",
                        "A port used by POP3 or IMAP's cleartext variant (110/143) was found open and reachable"
                                + " (deep scan identified it as " + representative.serviceSummary() + "). Unlike "
                                + "their TLS-wrapped counterparts (995/993), these protocols send credentials and "
                                + "mail content unencrypted unless a client separately negotiates STARTTLS after "
                                + "connecting.",
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

            details.stream()
                    .filter(d -> hasAnySshWeakAlgorithm(d.scriptOutputs()))
                    .findFirst()
                    .ifPresent(d -> findings.add(sshWeakAlgorithmFinding(hostname, portId, d.scriptOutputs())));
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

    private static final List<String> SSH_WEAK_SCRIPT_OUTPUT_KEYS =
            List.of("ssh-weak-kex", "ssh-weak-hostkey", "ssh-weak-cipher", "ssh-weak-mac");

    private static boolean hasAnySshWeakAlgorithm(Map<String, String> scriptOutputs) {
        return SSH_WEAK_SCRIPT_OUTPUT_KEYS.stream()
                .anyMatch(key -> scriptOutputs.get(key) != null && !scriptOutputs.get(key).isBlank());
    }

    private static RawFinding sshWeakAlgorithmFinding(String hostname, int portId, Map<String, String> scriptOutputs) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("port", portId);
        List<String> summaryParts = new ArrayList<>();
        for (String key : SSH_WEAK_SCRIPT_OUTPUT_KEYS) {
            String value = scriptOutputs.get(key);
            if (value != null && !value.isBlank()) {
                evidence.put(key.replace("ssh-weak-", "weak") + "Algorithms", value);
                summaryParts.add(key.substring("ssh-weak-".length()) + ": " + value);
            }
        }
        return new RawFinding(
                "NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED",
                Severity.HIGH,
                Category.NETWORK,
                "SSH server offers a deprecated/weak algorithm",
                "The deep scan's SSH handshake probe found this server is willing to negotiate at least one "
                        + "deprecated or cryptographically weak algorithm (" + String.join("; ", summaryParts)
                        + ") - a client that still offers it (an outdated SSH client, or one deliberately "
                        + "downgraded by an attacker) can still use it, regardless of what a modern client "
                        + "would normally pick.",
                hostname + ":" + portId,
                evidence);
    }
}
