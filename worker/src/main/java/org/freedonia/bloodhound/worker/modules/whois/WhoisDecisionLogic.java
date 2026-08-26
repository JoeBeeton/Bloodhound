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
        if (fields.expiryDate() == null) {
            return List.of();
        }
        if (fields.expiryDate().isBefore(now.plus(EXPIRING_SOON_DAYS, ChronoUnit.DAYS))) {
            return List.of(new RawFinding(
                    "WHOIS_EXPIRY_APPROACHING",
                    Severity.HIGH,
                    Category.WHOIS,
                    "Domain registration expiring soon",
                    "This domain's registration expires within 30 days.",
                    hostname,
                    Map.of("expiryDate", fields.expiryDate().toString())));
        }
        return List.of();
    }
}
