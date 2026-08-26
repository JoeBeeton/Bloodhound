package org.freedonia.bloodhound.worker.modules.typosquat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.springframework.stereotype.Component;

/**
 * Brand-protection scan: generates typosquat/lookalike-domain candidates for
 * the target's own root hostname (not its subdomains - lookalikes are of the
 * brand/root domain, so this is never one of SUBDOMAIN_FANOUT_MODULE_TYPES on
 * the central-server side), checks which are registered, and reports both the
 * findings (RawFinding, same as most other modules - registration status is
 * knowable within this one scan, no target history needed) and the full
 * checked-candidate list via rawMetadata (for central-server to persist into
 * typosquat_candidates for tracking/UI display, mirroring how TECH_FINGERPRINT
 * hands back structured per-hostname data).
 */
@Component
public class TyposquatMonitorModule implements ScanModule {

    private final TyposquatChecker checker = new TyposquatChecker();

    @Override
    public String moduleType() {
        return "TYPOSQUAT_MONITOR";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate(context.hostname());
        List<TyposquatChecker.CheckedCandidate> checked = checker.check(candidates);
        List<RawFinding> findings = TyposquatDecisionLogic.decide(checked);

        List<Map<String, Object>> candidateMetadata = new ArrayList<>();
        for (TyposquatChecker.CheckedCandidate candidate : checked) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("domain", candidate.domain());
            entry.put("permutationType", candidate.permutationType());
            entry.put("isRegistered", !candidate.resolvedIps().isEmpty());
            entry.put("resolvedIp", candidate.resolvedIps().isEmpty() ? null : candidate.resolvedIps().get(0));
            entry.put(
                    "registrationDate",
                    candidate.registrationDate() == null ? null : candidate.registrationDate().toString());
            candidateMetadata.add(entry);
        }

        Map<String, Object> rawMetadata = new LinkedHashMap<>();
        rawMetadata.put("candidates", candidateMetadata);
        rawMetadata.put("generated", candidates.size());
        return new ModuleResult(findings, rawMetadata);
    }
}
