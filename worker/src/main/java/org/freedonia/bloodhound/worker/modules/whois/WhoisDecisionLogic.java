package org.freedonia.bloodhound.worker.modules.whois;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure interpretation of a WhoisFields lookup into findings - no network
 * calls. Only WHOIS_EXPIRY_APPROACHING is decided here: WHOIS_REGISTRANT_CHANGED
 * needs this target's history, which only central-server's WhoisIngestionService
 * can see (this module is stateless, matching the SubdomainEnumModule pattern).
 */
public final class WhoisDecisionLogic {

    private static final long EXPIRING_SOON_DAYS = 30;

    private WhoisDecisionLogic() {}

    public static List<RawFinding> decide(String hostname, WhoisFields fields, Instant now) {
        List<RawFinding> findings = new java.util.ArrayList<>();

        if (fields.expiryDate() != null && fields.expiryDate().isBefore(now.plus(EXPIRING_SOON_DAYS, ChronoUnit.DAYS))) {
            findings.add(new RawFinding(
                    "WHOIS_EXPIRY_APPROACHING",
                    Severity.HIGH,
                    Category.WHOIS,
                    "Domain registration expiring soon",
                    "This domain's registration expires within 30 days.",
                    hostname,
                    Map.of("expiryDate", fields.expiryDate().toString())));
        }

        // Only judged when statusCodes actually came back non-empty - a registry this app
        // couldn't get status data from at all (RDAP omits it, or the raw-text fallback's
        // "Domain Status:" line format didn't match) means "unknown", not "unlocked". Matches
        // this module's own DNS-sibling's best-effort-signal precedent (DNS_DKIM_NOT_DETECTED):
        // silence over a guess when the data just isn't there.
        //
        // Spaces stripped before matching: RDAP's own EPP status vocabulary is spaced lowercase
        // ("client transfer prohibited"), while ICANN-2013-RAA raw-WHOIS text uses concatenated
        // camelCase ("clientTransferProhibited") - lowercasing then stripping spaces normalizes
        // both fetch paths' shapes to the same comparable form.
        if (!fields.statusCodes().isEmpty()
                && fields.statusCodes().stream().noneMatch(s -> normalizeStatus(s).contains("transferprohibited"))) {
            findings.add(new RawFinding(
                    "WHOIS_NO_TRANSFER_LOCK",
                    Severity.MEDIUM,
                    Category.WHOIS,
                    "Domain has no transfer lock",
                    "This domain's WHOIS/RDAP status shows no clientTransferProhibited (or equivalent registry) "
                            + "lock, making it easier for an attacker with access to the registrant account or "
                            + "registrar to initiate an unauthorized transfer away from the current registrar.",
                    hostname,
                    Map.of("statusCodes", fields.statusCodes())));
        }

        return findings;
    }

    private static String normalizeStatus(String status) {
        return status.toLowerCase(java.util.Locale.ROOT).replace(" ", "");
    }
}
