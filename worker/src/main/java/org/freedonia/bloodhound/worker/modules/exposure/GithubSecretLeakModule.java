package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Tier 2: searches public GitHub code for this target's own root domain, then re-checks any hit
 * with {@link SecretPatternScanner} (see {@link GithubSecretLeakDecisionLogic}). Only ever
 * dispatched via TargetController's authorization-gated deep-scan endpoint, same as every other
 * Tier 2 module.
 *
 * <p>Deliberately target-scoped (apex only, once per target - see
 * {@code ScanRunService#TIER2_TARGET_SCOPED_MODULE_TYPES}), not fanned out per subdomain, same
 * domain-wide reasoning as {@code DnsZoneExploitModule}: a GitHub code-search for this domain
 * isn't a property of any one subdomain, and (unlike most Tier 2 checks) also contends with a
 * genuinely scarce GLOBAL rate limit shared across every target, not just this target's own
 * infrastructure - see {@code ScanJobRepository#claim}'s GITHUB_SECRET_SEARCH advisory-lock
 * branch, which caps how many of these jobs run at once system-wide, the same shape
 * ZAP_ACTIVE_SCAN's own shared-bottleneck cap already uses.
 *
 * <p>No-op (findings empty, {@code enabled=false} in the result metadata) whenever the target's
 * org has no GitHub token configured via the admin UI - the common case for most orgs/deployments
 * - same "disabled, not a bug" convention as an unset {@code HIBP_API_KEY}.
 */
@Component
public class GithubSecretLeakModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(GithubSecretLeakModule.class);

    private final GithubSecretLeakFetcher fetcher;

    public GithubSecretLeakModule(GithubSecretLeakFetcher fetcher) {
        this.fetcher = fetcher;
    }

    @Override
    public String moduleType() {
        return "GITHUB_SECRET_SEARCH";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        try {
            GithubSecretLeakFetcher.FetchResult result = fetcher.fetch(context.targetId(), context.hostname());
            if (!result.enabled()) {
                log.debug(
                        "github secret search disabled for {} - no GitHub token configured for its org", context.hostname());
                return new ModuleResult(List.of(), Map.of("enabled", false));
            }
            List<RawFinding> findings = GithubSecretLeakDecisionLogic.decide(context.hostname(), result);
            return new ModuleResult(
                    findings,
                    Map.of(
                            "enabled", true,
                            "candidatesChecked", result.candidateFiles().size(),
                            "findingCount", findings.size()));
        } catch (Exception e) {
            throw new ScanModuleException("github secret search failed for " + context.hostname() + ": " + e.getMessage(), e);
        }
    }
}
