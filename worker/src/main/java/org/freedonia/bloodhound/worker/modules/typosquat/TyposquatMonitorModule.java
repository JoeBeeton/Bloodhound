package org.freedonia.bloodhound.worker.modules.typosquat;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.springframework.beans.factory.annotation.Value;
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

    private final TyposquatChecker checker;

    public TyposquatMonitorModule(
            @Value("${bloodhound.worker.screenshotter.base-url:http://screenshotter:3000}") String screenshotterBaseUrl,
            @Value("${bloodhound.worker.screenshotter.api-key:}") String screenshotterApiKey) {
        this.checker = new TyposquatChecker(new TyposquatScreenshotter(screenshotterBaseUrl, screenshotterApiKey));
    }

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
        List<TyposquatChecker.CheckedCandidate> checked = checker.check(context.hostname(), candidates);
        List<RawFinding> findings = TyposquatDecisionLogic.decide(checked);

        List<Map<String, Object>> candidateMetadata = new ArrayList<>();
        for (TyposquatChecker.CheckedCandidate candidate : checked) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("domain", candidate.domain());
            entry.put("permutationType", candidate.permutationType());
            // A wildcard-artifact candidate technically resolves, but that resolution came from its
            // parent zone answering for literally any subdomain, not from anyone registering this
            // specific label - treated as unregistered here (not just excluded from findings, see
            // TyposquatDecisionLogic) so it also never shows up in the target's tracked "Brand
            // protection" candidate list, which is driven by is_registered independent of findings.
            boolean isRegistered = !candidate.resolvedIps().isEmpty() && !candidate.wildcardArtifact();
            entry.put("isRegistered", isRegistered);
            entry.put("resolvedIp", isRegistered ? candidate.resolvedIps().get(0) : null);
            entry.put("registrationDate", isRegistered && candidate.registrationDate() != null
                    ? candidate.registrationDate().toString()
                    : null);
            entry.put("visualSimilarityPercent", isRegistered ? candidate.visualSimilarityPercent() : null);
            // Base64 in the JSON metadata blob (not a separate upload channel) - same pattern the
            // rest of this module's result already uses to hand structured data back to
            // central-server for persistence (see TyposquatIngestionService). Screenshots are
            // deliberately small (800x600, see TyposquatScreenshotter) so this stays a modest
            // handful of KB per genuine candidate, not a bulk-transfer concern.
            entry.put(
                    "screenshotBase64",
                    isRegistered && candidate.screenshotPng() != null
                            ? Base64.getEncoder().encodeToString(candidate.screenshotPng())
                            : null);
            candidateMetadata.add(entry);
        }

        Map<String, Object> rawMetadata = new LinkedHashMap<>();
        rawMetadata.put("candidates", candidateMetadata);
        rawMetadata.put("generated", candidates.size());
        return new ModuleResult(findings, rawMetadata);
    }
}
