package org.freedonia.bloodhound.server.subdomain.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingRepository.WafStatus;
import org.freedonia.bloodhound.server.subdomain.Subdomain;
import org.freedonia.bloodhound.server.tls.TlsGradeCalculator;

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
        boolean wafScanned,
        /** A+ through F, or null when this host has no open TLS findings yet (not yet TLS-scanned) - see TlsGradeCalculator. */
        String tlsGrade,
        /** Which open findings drove tlsGrade and why - empty when tlsGrade is null or the host is a clean A+/A. */
        List<TlsGradeCalculator.Factor> tlsGradeFactors) {

    public static SubdomainSummary from(Subdomain s) {
        return from(s, null, TlsGradeCalculator.NOT_SCANNED);
    }

    public static SubdomainSummary from(Subdomain s, WafStatus wafStatus, TlsGradeCalculator.Result tlsGrade) {
        return new SubdomainSummary(
                s.id(),
                s.hostname(),
                s.firstSeenAt(),
                s.lastSeenAt(),
                s.source(),
                s.isActive(),
                s.currentIpAddresses(),
                wafStatus != null ? wafStatus.vendor() : null,
                wafStatus != null && wafStatus.scanned(),
                tlsGrade.grade(),
                tlsGrade.factors());
    }
}
