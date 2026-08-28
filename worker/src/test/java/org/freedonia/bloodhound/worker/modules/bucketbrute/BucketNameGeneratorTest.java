package org.freedonia.bloodhound.worker.modules.bucketbrute;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class BucketNameGeneratorTest {

    @Test
    void singlePartTld_usesLabelAsStem() {
        List<String> candidates = BucketNameGenerator.generate("acme.com");

        assertThat(candidates).contains("acme", "acme-backup", "acmebackup", "www-acme", "acme-2025", "acme-01");
    }

    @Test
    void multiPartTld_usesLastDotSplitStemWithKnownLimitation() {
        // Documented shared limitation with PermutationGenerator/WhoisFetcher.tldOf(): the
        // simple last-dot split isn't public-suffix-list-aware, so "jaja.co.uk" yields the
        // sanitized stem "jaja-co", not "jaja". Locking in the actual (imperfect) behavior.
        List<String> candidates = BucketNameGenerator.generate("jaja.co.uk");

        assertThat(candidates).contains("jaja-co", "jaja-co-backup");
        assertThat(candidates).noneMatch(c -> c.equals("jaja") || c.equals("jaja-backup"));
    }

    @Test
    void generatedNames_areAllBucketNameSafe() {
        List<String> candidates = BucketNameGenerator.generate("my_weird--Domain.example.com");

        assertThat(candidates).allSatisfy(c -> {
            assertThat(c).matches("[a-z0-9-]+");
            assertThat(c).doesNotStartWith("-").doesNotEndWith("-");
        });
    }

    @Test
    void tooShortStem_yieldsNoCandidates() {
        assertThat(BucketNameGenerator.generate("a.com")).isEmpty();
        assertThat(BucketNameGenerator.generate("...com")).isEmpty();
    }

    @Test
    void nullHostname_yieldsNoCandidates() {
        assertThat(BucketNameGenerator.generate(null)).isEmpty();
    }

    @Test
    void candidateCount_landsInExpectedRange() {
        // Chosen scope: a larger permutation set (200-500 candidates).
        List<String> candidates = BucketNameGenerator.generate("acme.com");

        assertThat(candidates.size()).isBetween(200, 500);
    }

    @Test
    void noDuplicateCandidates() {
        List<String> candidates = BucketNameGenerator.generate("acme.com");

        assertThat(candidates).doesNotHaveDuplicates();
    }

    @Test
    void generationIsDeterministic() {
        assertThat(BucketNameGenerator.generate("acme.com")).isEqualTo(BucketNameGenerator.generate("acme.com"));
    }
}
