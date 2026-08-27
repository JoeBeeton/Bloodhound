package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.worker.modules.subdomain.SubdomainDnsResolver;
import org.freedonia.bloodhound.worker.modules.whois.WhoisFetcher;
import org.junit.jupiter.api.Test;

class TyposquatCheckerTest {

    private final SubdomainDnsResolver dnsResolver = mock(SubdomainDnsResolver.class);
    private final WhoisFetcher whoisFetcher = mock(WhoisFetcher.class);
    private final TyposquatChecker checker = new TyposquatChecker(dnsResolver, whoisFetcher);

    /**
     * Regression test for a real false positive: jaja.co.uk permuted (via HYPHENATION) into
     * jaja.c-o.uk, where c-o.uk itself is wildcarded (a squatter catching typos of "co.uk"
     * wholesale) so ANY subdomain of it resolves - not because "jaja" specifically was
     * registered. The checker must probe c-o.uk's own wildcard status and flag the candidate
     * as an artifact rather than a genuine registration.
     */
    @Test
    void resolvingCandidateUnderAWildcardedParentZone_flaggedAsWildcardArtifact() {
        var candidate = new PermutationGenerator.Candidate("jaja.c-o.uk", "HYPHENATION");
        when(dnsResolver.resolveAll(List.of("jaja.c-o.uk"))).thenReturn(Map.of("jaja.c-o.uk", List.of("203.0.113.5")));
        // Any probe hostname (identifiable by its "bh-wildcard-probe-" prefix, distinct from the
        // real candidate batch above even though both happen to end in the same TLD) also resolves -
        // the zone is wildcarded.
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname()))
                .thenAnswer(inv -> {
                    @SuppressWarnings("unchecked")
                    var hostnames = (java.util.Collection<String>) inv.getArgument(0);
                    String probeHostname = hostnames.iterator().next();
                    return Map.of(probeHostname, List.of("203.0.113.99"));
                });

        List<TyposquatChecker.CheckedCandidate> result = checker.check(List.of(candidate));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).isNotEmpty();
        assertThat(result.get(0).wildcardArtifact()).isTrue();
        // Never worth a WHOIS lookup for a wildcard artifact - it isn't a real registration signal.
        org.mockito.Mockito.verifyNoInteractions(whoisFetcher);
    }

    @Test
    void resolvingCandidateWhoseParentZoneIsNotWildcarded_notFlaggedAsArtifact() throws Exception {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        // The wildcard probe under "com" (jjaa.com's parent) resolves to nothing - com isn't wildcarded.
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(whoisFetcher.fetch("jjaa.com")).thenThrow(new RuntimeException("no whois data"));

        List<TyposquatChecker.CheckedCandidate> result = checker.check(List.of(candidate));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).containsExactly("198.51.100.7");
        assertThat(result.get(0).wildcardArtifact()).isFalse();
    }

    @Test
    void nonResolvingCandidate_neverProbedForWildcard() {
        var candidate = new PermutationGenerator.Candidate("dead.com", "OMISSION");
        when(dnsResolver.resolveAll(List.of("dead.com"))).thenReturn(Map.of());

        List<TyposquatChecker.CheckedCandidate> result = checker.check(List.of(candidate));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).isEmpty();
        assertThat(result.get(0).wildcardArtifact()).isFalse();
        // Only one resolveAll call - the initial candidate batch. No second (probe) batch was ever needed.
        org.mockito.Mockito.verify(dnsResolver, org.mockito.Mockito.times(1)).resolveAll(any());
    }

    @Test
    void emptyInput_returnsEmpty_neverCallsResolver() {
        List<TyposquatChecker.CheckedCandidate> result = checker.check(List.of());
        assertThat(result).isEmpty();
        org.mockito.Mockito.verifyNoInteractions(dnsResolver);
    }

    @SuppressWarnings("unchecked")
    private static java.util.Collection<String> argThatContainsAWildcardProbeHostname() {
        return org.mockito.ArgumentMatchers.argThat((java.util.Collection<String> arg) -> arg != null
                && arg.stream().anyMatch(h -> h.startsWith("bh-wildcard-probe-")));
    }
}
