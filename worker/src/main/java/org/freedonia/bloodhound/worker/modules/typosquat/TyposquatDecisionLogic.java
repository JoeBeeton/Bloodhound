package org.freedonia.bloodhound.worker.modules.typosquat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure decision half: a checked candidate becomes a finding purely because it
 * resolves (registered + live) - registration alone is the actionable
 * signal, per the product decision that proving active phishing content is a
 * separate, paid-tooling-dependent capability out of scope here. No database
 * access, no "is this new" comparison needed (unlike SubdomainIngestionService's
 * findings): whether a candidate is registered is knowable from this scan
 * alone, so the module emits these findings directly rather than routing
 * through a central-server ingestion detour the way SUBDOMAIN_ENUM/WHOIS do.
 *
 * <p>A candidate flagged {@code wildcardArtifact} by {@link TyposquatChecker}
 * is never emitted as a finding, even though it technically resolves: that
 * resolution came from its parent zone answering for literally any
 * subdomain, not from anyone registering this specific lookalike label - not
 * real typosquatting signal, just noise from an unrelated wildcarded zone.
 */
public final class TyposquatDecisionLogic {

    private TyposquatDecisionLogic() {}

    public static List<RawFinding> decide(List<TyposquatChecker.CheckedCandidate> checked) {
        List<RawFinding> findings = new ArrayList<>();
        for (TyposquatChecker.CheckedCandidate candidate : checked) {
            if (candidate.resolvedIps().isEmpty() || candidate.wildcardArtifact()) {
                continue;
            }
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("permutationType", candidate.permutationType());
            evidence.put("resolvedIps", candidate.resolvedIps());
            if (candidate.registrationDate() != null) {
                evidence.put("registrationDate", candidate.registrationDate().toString());
            }
            String humanType =
                    candidate.permutationType().toLowerCase(Locale.ROOT).replace('_', ' ');
            findings.add(new RawFinding(
                    "TYPOSQUAT_DOMAIN_REGISTERED",
                    Severity.HIGH,
                    Category.BRAND,
                    "Registered lookalike domain: " + candidate.domain(),
                    "A domain closely resembling this target's own (a " + humanType
                            + " variant) is registered and actively resolving, which is consistent with "
                            + "typosquatting or brand-impersonation infrastructure - though it can occasionally be "
                            + "a coincidentally similarly-named, unrelated legitimate site.",
                    candidate.domain(),
                    evidence));
        }
        return findings;
    }
}
