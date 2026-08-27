package org.freedonia.bloodhound.worker.modules.typosquat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.worker.modules.subdomain.SubdomainDnsResolver;
import org.freedonia.bloodhound.worker.modules.whois.WhoisFetcher;

/**
 * Fetch half: resolves each candidate's DNS (reusing the same public-resolver
 * approach as subdomain enumeration - Cloudflare 1.1.1.1, bounded/concurrent)
 * and, only for candidates that actually resolve, does a best-effort WHOIS/RDAP
 * lookup for the registration date (reusing WhoisModule's RDAP-first fetcher).
 * A WHOIS failure for one candidate never fails the whole check - registration
 * date is a nice-to-have signal, not required to flag a resolving lookalike.
 *
 * <p>Also probes for wildcard DNS on each resolving candidate's parent zone
 * (same "does a definitely-nonexistent name under this zone resolve too"
 * technique {@code DnsRecordFetcher.probeWildcard} already uses for a
 * target's own domain) - see {@link #wildcardParent} for why this matters
 * specifically for typosquat candidates, given {@link PermutationGenerator}'s
 * documented last-dot-only TLD split.
 */
public class TyposquatChecker {

    public record CheckedCandidate(
            String domain,
            String permutationType,
            List<String> resolvedIps,
            Instant registrationDate,
            boolean wildcardArtifact) {}

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

        // Only probe parents of candidates that actually resolved - a wildcard check against a
        // dead candidate is wasted work, and this keeps the probe batch small.
        Set<String> parentsToProbe = new HashSet<>();
        for (PermutationGenerator.Candidate candidate : candidates) {
            if (!resolved.getOrDefault(candidate.domain(), List.of()).isEmpty()) {
                String parent = wildcardParent(candidate.domain());
                if (parent != null) {
                    parentsToProbe.add(parent);
                }
            }
        }
        Map<String, String> probeHostnameByParent = new java.util.LinkedHashMap<>();
        for (String parent : parentsToProbe) {
            probeHostnameByParent.put(
                    parent, "bh-wildcard-probe-" + UUID.randomUUID().toString().replace("-", "") + "." + parent);
        }
        Map<String, List<String>> probeResults =
                probeHostnameByParent.isEmpty() ? Map.of() : dnsResolver.resolveAll(probeHostnameByParent.values());
        Set<String> wildcardParents = new HashSet<>();
        probeHostnameByParent.forEach((parent, probeHostname) -> {
            if (!probeResults.getOrDefault(probeHostname, List.of()).isEmpty()) {
                wildcardParents.add(parent);
            }
        });

        List<CheckedCandidate> result = new ArrayList<>();
        for (PermutationGenerator.Candidate candidate : candidates) {
            List<String> ips = resolved.getOrDefault(candidate.domain(), List.of());
            boolean wildcardArtifact = !ips.isEmpty() && wildcardParents.contains(wildcardParent(candidate.domain()));
            Instant registrationDate = ips.isEmpty() || wildcardArtifact ? null : tryWhois(candidate.domain());
            result.add(new CheckedCandidate(candidate.domain(), candidate.permutationType(), ips, registrationDate, wildcardArtifact));
        }
        return result;
    }

    /**
     * The zone to probe for wildcard DNS: everything after the candidate's
     * first dot. For a normal two-label candidate ("jaj4.com"), that's just
     * the TLD ("com") - harmless and correctly never wildcarded, nobody
     * wildcards a public registry. The case that actually matters is a
     * hyphenation/omission/etc. candidate generated from a target whose real
     * domain has a multi-part TLD - {@link PermutationGenerator}'s label/TLD
     * split is a simple last-dot split (a documented limitation: it doesn't
     * know "co.uk" is one unit), so a candidate like "jaja.co.uk" typo'd as
     * "jaja.c-o.uk" is actually the label "jaja" under the REAL, separately-
     * registrable domain "c-o.uk" - which is commonly registered by a domain
     * squatter specifically to catch typos of "co.uk" wholesale, wildcarding
     * every subdomain to catch traffic regardless of what came before the
     * dot. Confirmed for real: jaja.c-o.uk resolving turned out to have
     * nothing to do with "jaja" specifically - c-o.uk answers for anything.
     * Without this check, that candidate (and every other single-label
     * candidate sharing the same multi-part-TLD confusion) would be flagged
     * as a registered lookalike purely because of that unrelated wildcard.
     */
    private static String wildcardParent(String candidateDomain) {
        int dot = candidateDomain.indexOf('.');
        if (dot < 0 || dot == candidateDomain.length() - 1) {
            return null;
        }
        return candidateDomain.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private Instant tryWhois(String domain) {
        try {
            return whoisFetcher.fetch(domain).createdDate();
        } catch (Exception e) {
            return null;
        }
    }
}
