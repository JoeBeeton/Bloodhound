package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.Map;

/**
 * One open TCP port from a Tier 2 deep scan (naabu for discovery, zgrab2 for
 * identification - see DeepPortScanModule), with whatever service/version
 * was inferred from its banner or HTTP Server header, and any
 * DeepPortScanModule-specific probe results (currently just ftp-anon) keyed
 * into scriptOutputs. serviceName/serviceProduct/serviceVersion are null
 * when nothing could be inferred - not every open port yields a positive ID.
 *
 * @param addressFamily "IPv4" or "IPv6" - which of the host's addresses this
 *     port was found open on (see DeepPortScanModule, which now scans one
 *     address per family). {@link DeepPortScanDecisionLogic} unions this
 *     across families sharing the same port number into one finding's
 *     evidence rather than reporting duplicates.
 */
public record PortDetail(
        int portId,
        String serviceName,
        String serviceProduct,
        String serviceVersion,
        Map<String, String> scriptOutputs,
        String addressFamily) {

    /** A short human-readable summary for finding evidence, e.g. "vsftpd 3.0.3" or "ftp" - never blank. */
    public String serviceSummary() {
        if (serviceProduct != null && serviceVersion != null) {
            return serviceProduct + " " + serviceVersion;
        }
        if (serviceProduct != null) {
            return serviceProduct;
        }
        return serviceName != null ? serviceName : "unknown";
    }
}
