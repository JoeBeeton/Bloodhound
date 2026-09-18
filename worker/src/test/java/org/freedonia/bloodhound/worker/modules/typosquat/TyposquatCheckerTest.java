package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;
import org.freedonia.bloodhound.worker.modules.subdomain.SubdomainDnsResolver;
import org.freedonia.bloodhound.worker.modules.whois.WhoisFetcher;
import org.junit.jupiter.api.Test;

class TyposquatCheckerTest {

    private static final String ROOT_HOSTNAME = "realsite.com";

    private final SubdomainDnsResolver dnsResolver = mock(SubdomainDnsResolver.class);
    private final WhoisFetcher whoisFetcher = mock(WhoisFetcher.class);
    private final TyposquatScreenshotter screenshotter = mock(TyposquatScreenshotter.class);
    private final TyposquatChecker checker = new TyposquatChecker(dnsResolver, whoisFetcher, screenshotter);

    private static byte[] solidPng(Color color) {
        try {
            BufferedImage image = new BufferedImage(100, 100, BufferedImage.TYPE_INT_RGB);
            var g = image.getGraphics();
            g.setColor(color);
            g.fillRect(0, 0, 100, 100);
            g.dispose();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

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

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).isNotEmpty();
        assertThat(result.get(0).wildcardArtifact()).isTrue();
        assertThat(result.get(0).screenshotPng()).isNull();
        assertThat(result.get(0).visualSimilarityPercent()).isNull();
        // Never worth a WHOIS lookup or a screenshot for a wildcard artifact - it isn't a real signal.
        verifyNoInteractions(whoisFetcher);
        verifyNoInteractions(screenshotter);
    }

    @Test
    void resolvingCandidateWhoseParentZoneIsNotWildcarded_notFlaggedAsArtifact() throws Exception {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        // The wildcard probe under "com" (jjaa.com's parent) resolves to nothing - com isn't wildcarded.
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(whoisFetcher.fetch("jjaa.com")).thenThrow(new RuntimeException("no whois data"));

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).containsExactly("198.51.100.7");
        assertThat(result.get(0).wildcardArtifact()).isFalse();
    }

    @Test
    void genuineCandidate_screenshotsBothRealSiteAndCandidate_computesSimilarity() {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(screenshotter.capture(ROOT_HOSTNAME)).thenReturn(solidPng(Color.BLUE));
        when(screenshotter.capture("jjaa.com")).thenReturn(solidPng(Color.BLUE));

        TyposquatChecker.CheckResult checkResult = checker.check(ROOT_HOSTNAME, List.of(candidate));

        assertThat(checkResult.candidates()).hasSize(1);
        assertThat(checkResult.candidates().get(0).screenshotPng()).isNotNull();
        assertThat(checkResult.candidates().get(0).visualSimilarityPercent()).isEqualTo(100);
        // The real site's own screenshot is returned too, for a UI side-by-side - not just consumed
        // internally for hashing.
        assertThat(checkResult.realSiteScreenshotPng()).isNotNull();
        verify(screenshotter, times(1)).capture(ROOT_HOSTNAME);
        verify(screenshotter, times(1)).capture("jjaa.com");
    }

    @Test
    void noGenuineCandidates_realSiteNeverScreenshotted_resultCarriesNullRealSiteScreenshot() {
        var candidate = new PermutationGenerator.Candidate("dead.com", "OMISSION");
        when(dnsResolver.resolveAll(List.of("dead.com"))).thenReturn(Map.of());

        TyposquatChecker.CheckResult checkResult = checker.check(ROOT_HOSTNAME, List.of(candidate));

        assertThat(checkResult.realSiteScreenshotPng()).isNull();
        verifyNoInteractions(screenshotter);
    }

    @Test
    void realSiteScreenshotFails_candidateGetsNoSimilarityScore_stillNoWastedScreenshotCall() {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(screenshotter.capture(ROOT_HOSTNAME)).thenReturn(null);

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result.get(0).screenshotPng()).isNull();
        assertThat(result.get(0).visualSimilarityPercent()).isNull();
        // The real site's screenshot failed to hash - never worth also screenshotting the candidate.
        verify(screenshotter, never()).capture("jjaa.com");
    }

    @Test
    void multipleGenuineCandidates_realSiteScreenshottedOnlyOnce() {
        var candidateA = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        var candidateB = new PermutationGenerator.Candidate("rea1site.com", "HOMOGLYPH");
        when(dnsResolver.resolveAll(List.of("jjaa.com", "rea1site.com")))
                .thenReturn(Map.of("jjaa.com", List.of("198.51.100.7"), "rea1site.com", List.of("198.51.100.8")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(screenshotter.capture(eq(ROOT_HOSTNAME))).thenReturn(solidPng(Color.GREEN));
        when(screenshotter.capture(eq("jjaa.com"))).thenReturn(solidPng(Color.RED));
        when(screenshotter.capture(eq("rea1site.com"))).thenReturn(solidPng(Color.GREEN));

        checker.check(ROOT_HOSTNAME, List.of(candidateA, candidateB));

        verify(screenshotter, times(1)).capture(ROOT_HOSTNAME);
    }

    @Test
    void nonResolvingCandidate_neverProbedForWildcardOrScreenshotted() {
        var candidate = new PermutationGenerator.Candidate("dead.com", "OMISSION");
        when(dnsResolver.resolveAll(List.of("dead.com"))).thenReturn(Map.of());

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).resolvedIps()).isEmpty();
        assertThat(result.get(0).wildcardArtifact()).isFalse();
        assertThat(result.get(0).screenshotPng()).isNull();
        // Only one resolveAll call - the initial candidate batch. No second (probe) batch was ever needed.
        verify(dnsResolver, times(1)).resolveAll(any());
        verifyNoInteractions(screenshotter);
    }

    @Test
    void emptyInput_returnsEmpty_neverCallsResolverOrScreenshotter() {
        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of()).candidates();
        assertThat(result).isEmpty();
        verifyNoInteractions(dnsResolver);
        verifyNoInteractions(screenshotter);
    }

    @Test
    void genuineCandidateWithMxRecords_mxConfiguredTrue() {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(dnsResolver.resolveMxHosts(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("mail.jjaa.com")));

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result.get(0).mxConfigured()).isTrue();
    }

    @Test
    void genuineCandidateWithNoMxRecords_mxConfiguredFalse() {
        var candidate = new PermutationGenerator.Candidate("jjaa.com", "TRANSPOSITION");
        when(dnsResolver.resolveAll(List.of("jjaa.com"))).thenReturn(Map.of("jjaa.com", List.of("198.51.100.7")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname())).thenReturn(Map.of());
        when(dnsResolver.resolveMxHosts(List.of("jjaa.com"))).thenReturn(Map.of());

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result.get(0).mxConfigured()).isFalse();
    }

    @Test
    void wildcardArtifact_neverProbedForMx() {
        var candidate = new PermutationGenerator.Candidate("jaja.c-o.uk", "HYPHENATION");
        when(dnsResolver.resolveAll(List.of("jaja.c-o.uk"))).thenReturn(Map.of("jaja.c-o.uk", List.of("203.0.113.5")));
        when(dnsResolver.resolveAll(argThatContainsAWildcardProbeHostname()))
                .thenAnswer(inv -> {
                    @SuppressWarnings("unchecked")
                    var hostnames = (java.util.Collection<String>) inv.getArgument(0);
                    String probeHostname = hostnames.iterator().next();
                    return Map.of(probeHostname, List.of("203.0.113.99"));
                });

        List<TyposquatChecker.CheckedCandidate> result = checker.check(ROOT_HOSTNAME, List.of(candidate)).candidates();

        assertThat(result.get(0).mxConfigured()).isFalse();
        verifyNoInteractions(whoisFetcher);
        verify(dnsResolver, never()).resolveMxHosts(any());
    }

    @SuppressWarnings("unchecked")
    private static java.util.Collection<String> argThatContainsAWildcardProbeHostname() {
        return org.mockito.ArgumentMatchers.argThat((java.util.Collection<String> arg) -> arg != null
                && arg.stream().anyMatch(h -> h.startsWith("bh-wildcard-probe-")));
    }
}
