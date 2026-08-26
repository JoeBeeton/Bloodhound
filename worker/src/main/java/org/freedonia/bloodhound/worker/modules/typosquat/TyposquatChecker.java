package org.freedonia.bloodhound.worker.modules.typosquat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.worker.modules.subdomain.SubdomainDnsResolver;
import org.freedonia.bloodhound.worker.modules.whois.WhoisFetcher;

/**
 * Fetch half: resolves each candidate's DNS (reusing the same public-resolver
 * approach as subdomain enumeration - Cloudflare 1.1.1.1, bounded/concurrent)
 * and, only for candidates that actually resolve, does a best-effort WHOIS/RDAP
 * lookup for the registration date (reusing WhoisModule's RDAP-first fetcher).
 * A WHOIS failure for one candidate never fails the whole check - registration
 * date is a nice-to-have signal, not required to flag a resolving lookalike.
 */
public class TyposquatChecker {

    public record CheckedCandidate(
            String domain, String permutationType, List<String> resolvedIps, Instant registrationDate) {}

    private final SubdomainDnsResolver dnsResolver;
    private final WhoisFetcher whoisFetcher;

    public TyposquatChecker() {
        this(new SubdomainDnsResolver(), new WhoisFetcher());
    }

    TyposquatChecker(SubdomainDnsResolver dnsResolver, WhoisFetcher whoisFetcher) {
        this.dnsResolver = dnsResolver;
        this.whoisFetcher = whoisFetcher;
    }

    public List<CheckedCandidate> check(List<PermutationGenerator.Candidate> candidates) {
        if (candidates.isEmpty()) {
            return List.of();
        }
        Map<String, List<String>> resolved =
                dnsResolver.resolveAll(candidates.stream().map(PermutationGenerator.Candidate::domain).toList());

        List<CheckedCandidate> result = new ArrayList<>();
        for (PermutationGenerator.Candidate candidate : candidates) {
            List<String> ips = resolved.getOrDefault(candidate.domain(), List.of());
            Instant registrationDate = ips.isEmpty() ? null : tryWhois(candidate.domain());
            result.add(new CheckedCandidate(candidate.domain(), candidate.permutationType(), ips, registrationDate));
        }
        return result;
    }

    private Instant tryWhois(String domain) {
        try {
            return whoisFetcher.fetch(domain).createdDate();
        } catch (Exception e) {
            return null;
        }
    }
}
