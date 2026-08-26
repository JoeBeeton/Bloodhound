package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class PermutationGeneratorTest {

    @Test
    void generatesExpectedOmissionsForShortLabel() {
        // "ab.com": dropping each of the 2 letters gives exactly "b.com" and "a.com".
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("ab.com");
        Map<String, String> byDomain = toMap(candidates);
        assertThat(byDomain).containsEntry("b.com", "OMISSION");
        assertThat(byDomain).containsEntry("a.com", "OMISSION");
    }

    @Test
    void generatesExpectedDuplicationsForShortLabel() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("ab.com");
        Map<String, String> byDomain = toMap(candidates);
        assertThat(byDomain).containsEntry("aab.com", "DUPLICATION");
        assertThat(byDomain).containsEntry("abb.com", "DUPLICATION");
    }

    @Test
    void generatesExpectedTranspositionForTwoLetterLabel() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("ab.com");
        Map<String, String> byDomain = toMap(candidates);
        assertThat(byDomain).containsEntry("ba.com", "TRANSPOSITION");
    }

    @Test
    void generatesExpectedHyphenationForTwoLetterLabel() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("ab.com");
        Map<String, String> byDomain = toMap(candidates);
        assertThat(byDomain).containsEntry("a-b.com", "HYPHENATION");
    }

    @Test
    void generatesGenericAndComSpecificTldSwaps() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("example.com");
        Map<String, String> byDomain = toMap(candidates);
        assertThat(byDomain).containsEntry("example.net", "TLD_SWAP");
        assertThat(byDomain).containsEntry("example.org", "TLD_SWAP");
        assertThat(byDomain).containsEntry("example.cm", "TLD_SWAP");
        assertThat(byDomain).containsEntry("example.om", "TLD_SWAP");
        // Non-.com TLDs don't get the .com-specific cm/om tricks.
        Map<String, String> nonCom = toMap(PermutationGenerator.generate("example.io"));
        assertThat(nonCom).doesNotContainKey("example.cm");
        assertThat(nonCom).containsEntry("example.net", "TLD_SWAP");
    }

    @Test
    void generatesHomoglyphSubstitutions() {
        // "goo.gl" -> "0" for "o" fires on the first occurrence of "o".
        Map<String, String> byDomain = toMap(PermutationGenerator.generate("goo.gl"));
        assertThat(byDomain).containsEntry("g0o.gl", "HOMOGLYPH");
    }

    @Test
    void generatesAdjacentKeySubstitutions() {
        // "a" is QWERTY-adjacent to q, w, s, z.
        Map<String, String> byDomain = toMap(PermutationGenerator.generate("a.com"));
        assertThat(byDomain).containsEntry("q.com", "ADJACENT_KEY_SUBSTITUTION");
        assertThat(byDomain).containsEntry("w.com", "ADJACENT_KEY_SUBSTITUTION");
        assertThat(byDomain).containsEntry("s.com", "ADJACENT_KEY_SUBSTITUTION");
        assertThat(byDomain).containsEntry("z.com", "ADJACENT_KEY_SUBSTITUTION");
    }

    @Test
    void neverIncludesTheOriginalDomainItself() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("example.com");
        assertThat(candidates).noneMatch(c -> c.domain().equals("example.com"));
    }

    @Test
    void everyCandidateIsUnique() {
        List<PermutationGenerator.Candidate> candidates = PermutationGenerator.generate("github.com");
        List<String> domains = candidates.stream().map(PermutationGenerator.Candidate::domain).toList();
        assertThat(domains).doesNotHaveDuplicates();
    }

    @Test
    void resultIsCappedAtOneHundredEvenForALongLabel() {
        List<PermutationGenerator.Candidate> candidates =
                PermutationGenerator.generate("aVeryLongDomainLabelThatGeneratesManyPermutations.com");
        assertThat(candidates.size()).isLessThanOrEqualTo(100);
    }

    @Test
    void hostnameWithNoDotProducesNoCandidates() {
        assertThat(PermutationGenerator.generate("localhost")).isEmpty();
    }

    @Test
    void nullHostnameProducesNoCandidates() {
        assertThat(PermutationGenerator.generate(null)).isEmpty();
    }

    private static Map<String, String> toMap(List<PermutationGenerator.Candidate> candidates) {
        return candidates.stream()
                .collect(Collectors.toMap(
                        PermutationGenerator.Candidate::domain, PermutationGenerator.Candidate::permutationType, (a, b) -> a));
    }
}
