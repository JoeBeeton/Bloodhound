package org.freedonia.bloodhound.worker.modules.typosquat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
 *
 * <p>For every "genuine" candidate (resolves, not a wildcard artifact),
 * captures a screenshot via {@link TyposquatScreenshotter} and computes a
 * {@link ScreenshotSimilarity}-based visual-similarity score against one shared
 * screenshot of the real target - a page that actually LOOKS like the real
 * one is a much stronger phishing/impersonation signal than registration
 * alone. Screenshotting is best-effort exactly like the WHOIS lookup below:
 * a failure never fails the candidate's registration finding, it just means
 * no similarity score for that one candidate. The real target's own
 * screenshot is returned too (see {@link CheckResult}), for a visual
 * side-by-side in the UI, not just as an internal hashing input.
 */
public class TyposquatChecker {

    public record CheckedCandidate(
            String domain,
            String permutationType,
            List<String> resolvedIps,
            Instant registrationDate,
            boolean wildcardArtifact,
            byte[] screenshotPng,
            Integer visualSimilarityPercent,
            boolean mxConfigured,
            TyposquatDecisionLogic.Disposition disposition) {
        public CheckedCandidate(
                String domain,
                String permutationType,
                List<String> resolvedIps,
                Instant registrationDate,
                boolean wildcardArtifact,
                byte[] screenshotPng,
                Integer visualSimilarityPercent,
                boolean mxConfigured) {
            this(domain, permutationType, resolvedIps, registrationDate, wildcardArtifact, screenshotPng,
                    visualSimilarityPercent, mxConfigured, TyposquatDecisionLogic.Disposition.UNKNOWN);
        }
    }

    /** realSiteScreenshotPng is null whenever no candidate ended up genuine enough to need the comparison baseline at all. */
    public record CheckResult(byte[] realSiteScreenshotPng, List<CheckedCandidate> candidates) {}

    private static final int PROBE_CONCURRENCY = 8;
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(30);

    private final SubdomainDnsResolver dnsResolver;
    private final WhoisFetcher whoisFetcher;
    private final TyposquatScreenshotter screenshotter;
    private final TyposquatPageProbe pageProbe;

    public TyposquatChecker(TyposquatScreenshotter screenshotter) {
        this(new SubdomainDnsResolver(), new WhoisFetcher(), screenshotter, new TyposquatPageProbe());
    }

    TyposquatChecker(
            SubdomainDnsResolver dnsResolver,
            WhoisFetcher whoisFetcher,
            TyposquatScreenshotter screenshotter,
            TyposquatPageProbe pageProbe) {
        this.dnsResolver = dnsResolver;
        this.whoisFetcher = whoisFetcher;
        this.screenshotter = screenshotter;
        this.pageProbe = pageProbe;
    }

    /**
     * {@code rootHostname} is the target's own real domain - screenshotted once (if there's at
     * least one genuine candidate to compare it against) and used as the visual-similarity
     * baseline for every candidate below, rather than a per-candidate re-fetch.
     */
    public CheckResult check(String rootHostname, List<PermutationGenerator.Candidate> candidates) {
        if (candidates.isEmpty()) {
            return new CheckResult(null, List.of());
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

        // Batched upfront (same shape as the IP resolution above), not per-candidate in the loop
        // below - only for genuine candidates, since a wildcard-artifact or non-resolving one is
        // never going to produce a finding regardless of its MX configuration.
        List<String> genuineDomains = candidates.stream()
                .map(PermutationGenerator.Candidate::domain)
                .filter(domain -> {
                    List<String> ips = resolved.getOrDefault(domain, List.of());
                    return !ips.isEmpty() && !wildcardParents.contains(wildcardParent(domain));
                })
                .toList();

        // The real target's own screenshot is the comparison baseline for every genuine
        // candidate below - captured at most once per check() call (not per candidate), and
        // only if there's actually at least one genuine candidate to compare it against.
        ScreenshotSimilarity.Fingerprint realFingerprint = null;
        byte[] realScreenshot = null;
        Map<String, TyposquatPageProbe.PageInfo> pages = Map.of();
        if (!genuineDomains.isEmpty()) {
            realScreenshot = screenshotter.capture(rootHostname);
            realFingerprint = ScreenshotSimilarity.fingerprint(realScreenshot);
            List<String> toProbe = new ArrayList<>(genuineDomains);
            toProbe.add(rootHostname);
            pages = probeAll(toProbe);
        }
        // A bot-challenge page as the baseline (seen live: revolut.com serves one to the scanner)
        // would make every other challenge or near-blank page look like a clone.
        TyposquatPageProbe.PageInfo brandPage = pages.get(rootHostname);
        boolean baselineComparable = brandPage == null || !brandPage.challengePage();
        // The real target's own MX/NS, resolved in the same batches as the candidates', so a
        // lookalike the brand itself operates (a defensive registration mailing into the brand's
        // own servers, or delegated to the brand's own nameservers) can be told apart from a
        // squatter's - see TyposquatDecisionLogic#isBrandControlled.
        List<String> mxAndNsLookups = new ArrayList<>(genuineDomains);
        if (!genuineDomains.isEmpty()) {
            mxAndNsLookups.add(rootHostname);
        }
        Map<String, List<String>> mxHosts =
                genuineDomains.isEmpty() ? Map.of() : dnsResolver.resolveMxHosts(mxAndNsLookups);
        Map<String, List<String>> nameServers =
                genuineDomains.isEmpty() ? Map.of() : dnsResolver.resolveNameServers(mxAndNsLookups);
        List<String> brandMx = mxHosts.getOrDefault(rootHostname, List.of());
        List<String> brandNs = nameServers.getOrDefault(rootHostname, List.of());

        List<CheckedCandidate> result = new ArrayList<>();
        for (PermutationGenerator.Candidate candidate : candidates) {
            List<String> ips = resolved.getOrDefault(candidate.domain(), List.of());
            boolean wildcardArtifact = !ips.isEmpty() && wildcardParents.contains(wildcardParent(candidate.domain()));
            boolean genuine = !ips.isEmpty() && !wildcardArtifact;
            Instant registrationDate = genuine ? tryWhois(candidate.domain()) : null;
            // "localhost" MX targets (seen live) can't receive anything - not mail routing.
            List<String> candidateMx = mxHosts.getOrDefault(candidate.domain(), List.of()).stream()
                    .filter(h -> !h.equalsIgnoreCase("localhost"))
                    .toList();
            boolean mxConfigured = !candidateMx.isEmpty();
            TyposquatPageProbe.PageInfo page = pages.get(candidate.domain());
            TyposquatDecisionLogic.Disposition disposition = genuine
                    ? TyposquatDecisionLogic.classify(
                            rootHostname,
                            brandMx,
                            brandNs,
                            candidateMx,
                            nameServers.getOrDefault(candidate.domain(), List.of()),
                            page)
                    : TyposquatDecisionLogic.Disposition.UNKNOWN;

            byte[] candidateScreenshot = null;
            Integer similarity = null;
            if (genuine && realFingerprint != null) {
                candidateScreenshot = screenshotter.capture(candidate.domain());
                ScreenshotSimilarity.Fingerprint candidateFingerprint =
                        ScreenshotSimilarity.fingerprint(candidateScreenshot);
                if (candidateFingerprint == null || !candidateFingerprint.informative()) {
                    // Undecodable or blank (an unrendered parking page, a "Redirecting..." stub) -
                    // not evidence of a live site, and nothing to compare.
                    candidateScreenshot = null;
                } else if (baselineComparable
                        && disposition == TyposquatDecisionLogic.Disposition.UNKNOWN
                        && (page == null || !page.challengePage())) {
                    similarity = ScreenshotSimilarity.similarityPercent(realFingerprint, candidateFingerprint);
                }
            }

            result.add(new CheckedCandidate(
                    candidate.domain(),
                    candidate.permutationType(),
                    ips,
                    registrationDate,
                    wildcardArtifact,
                    candidateScreenshot,
                    similarity,
                    mxConfigured,
                    disposition));
        }
        return new CheckResult(realScreenshot, result);
    }

    private Map<String, TyposquatPageProbe.PageInfo> probeAll(List<String> hostnames) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(PROBE_CONCURRENCY, hostnames.size()));
        try {
            Map<String, Future<TyposquatPageProbe.PageInfo>> futures = new LinkedHashMap<>();
            for (String hostname : hostnames) {
                futures.put(hostname, pool.submit(() -> pageProbe.probe(hostname)));
            }
            Map<String, TyposquatPageProbe.PageInfo> pages = new HashMap<>();
            for (Map.Entry<String, Future<TyposquatPageProbe.PageInfo>> entry : futures.entrySet()) {
                try {
                    TyposquatPageProbe.PageInfo page = entry.getValue().get(PROBE_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
                    if (page != null) {
                        pages.put(entry.getKey(), page);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception ignored) {
                    // unreachable or timed out - classified on DNS alone
                }
            }
            return pages;
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * The zone to probe for wildcard DNS: everything after the candidate's
     * first dot. For a normal two-label candidate ("examp1e.com"), that's just
     * the TLD ("com") - harmless and correctly never wildcarded, nobody
     * wildcards a public registry. The case that actually matters is a
     * hyphenation/omission/etc. candidate generated from a target whose real
     * domain has a multi-part TLD - {@link PermutationGenerator}'s label/TLD
     * split is a simple last-dot split (a documented limitation: it doesn't
     * know "co.uk" is one unit), so a candidate like "example.co.uk" typo'd as
     * "example.c-o.uk" is actually the label "example" under the REAL, separately-
     * registrable domain "c-o.uk" - which is commonly registered by a domain
     * squatter specifically to catch typos of "co.uk" wholesale, wildcarding
     * every subdomain to catch traffic regardless of what came before the
     * dot. Confirmed for real: example.c-o.uk resolving turned out to have
     * nothing to do with "example" specifically - c-o.uk answers for anything.
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
