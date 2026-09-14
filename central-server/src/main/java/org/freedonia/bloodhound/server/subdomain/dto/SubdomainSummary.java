package org.freedonia.bloodhound.server.subdomain.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingRepository.WafStatus;
import org.freedonia.bloodhound.server.subdomain.Subdomain;

public record SubdomainSummary(
        UUID id,
        String hostname,
        Instant firstSeenAt,
        Instant lastSeenAt,
        String source,
        boolean isActive,
        List<String> currentIpAddresses,
        /** The WAF product nuclei identified for this host (e.g. "cloudflare"), or null if either
         * no WAF was detected or nuclei hasn't scanned this host yet - see {@code wafScanned}. */
        String wafVendor,
        /** True once nuclei has scanned this host at all - disambiguates "scanned, no WAF found"
         * from "not yet scanned" for callers rendering wafVendor == null (the Attack Surface Map's
         * WAF badge, in particular: outline vs. no badge at all). */
        boolean wafScanned) {

    public static SubdomainSummary from(Subdomain s) {
        return from(s, null);
    }

    public static SubdomainSummary from(Subdomain s, WafStatus wafStatus) {
        return new SubdomainSummary(
                s.id(),
                s.hostname(),
                s.firstSeenAt(),
                s.lastSeenAt(),
                s.source(),
                s.isActive(),
                s.currentIpAddresses(),
                wafStatus != null ? wafStatus.vendor() : null,
                wafStatus != null && wafStatus.scanned());
    }
}
