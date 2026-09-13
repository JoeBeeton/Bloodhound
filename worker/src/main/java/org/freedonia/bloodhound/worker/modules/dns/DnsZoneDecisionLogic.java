package org.freedonia.bloodhound.worker.modules.dns;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of already-fetched per-nameserver zone-check results into findings - no network calls. */
public final class DnsZoneDecisionLogic {

    private DnsZoneDecisionLogic() {}

    public static List<RawFinding> decide(List<DnsZoneFetcher.NsCheckResult> results) {
        List<RawFinding> findings = new ArrayList<>();
        for (DnsZoneFetcher.NsCheckResult r : results) {
            if (!r.reachable()) {
                continue; // no evidence either way - see NsCheckResult
            }
            if (r.axfrAllowed()) {
                findings.add(new RawFinding(
                        "DNS_ZONE_TRANSFER_ALLOWED",
                        Severity.CRITICAL,
                        Category.DNS,
                        "DNS zone transfer (AXFR) allowed",
                        "This nameserver answered an unauthenticated zone transfer request, disclosing the "
                                + "domain's complete DNS zone - every subdomain, internal hostname, and record it "
                                + "holds - in a single query.",
                        r.nameserver(),
                        Map.of("recordCount", r.axfrRecordCount())));
            }
            if (!r.answeredAuthoritatively()) {
                findings.add(new RawFinding(
                        "DNS_NS_LAME_DELEGATION",
                        Severity.MEDIUM,
                        Category.DNS,
                        "Lame NS delegation",
                        "This nameserver is listed as authoritative for the domain but did not answer "
                                + "authoritatively for its zone, indicating a stale or misconfigured delegation.",
                        r.nameserver(),
                        Map.of()));
            }
        }
        return findings;
    }
}
