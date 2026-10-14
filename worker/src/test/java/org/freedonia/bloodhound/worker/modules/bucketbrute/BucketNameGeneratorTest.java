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

    @Test
    void smallWordlist_isCloudBrutesCuratedListNotTheOldHandRolledOne() {
        // "filestorage" and "productcontent" are real CloudBrute storage_small.txt terms that were
        // never in this project's old hand-rolled 85-term list - their presence confirms the swap
        // actually happened, not just that *a* wordlist is being used.
        List<String> candidates = BucketNameGenerator.generate("acme.com");

        assertThat(candidates).contains("acme-filestorage", "acme-productcontent");
    }

    @Test
    void generateFromLargeWordlist_producesHyphenAndNoHyphenJoinsFromTheRequestedSlice() {
        BucketNameGenerator.LargeWordlistBatch batch = BucketNameGenerator.generateFromLargeWordlist("acme.com", 0, 5);

        assertThat(batch.candidates()).isNotEmpty().allSatisfy(c -> assertThat(c).startsWith("acme"));
        assertThat(batch.nextOffset()).isEqualTo(5);
    }

    @Test
    void generateFromLargeWordlist_sameOffsetAndBatchSize_isDeterministic() {
        BucketNameGenerator.LargeWordlistBatch first = BucketNameGenerator.generateFromLargeWordlist("acme.com", 200, 10);
        BucketNameGenerator.LargeWordlistBatch second = BucketNameGenerator.generateFromLargeWordlist("acme.com", 200, 10);

        assertThat(first.candidates()).isEqualTo(second.candidates());
        assertThat(first.nextOffset()).isEqualTo(second.nextOffset());
    }

    @Test
    void generateFromLargeWordlist_consecutiveBatches_advanceWithoutGapOrOverlap() {
        int total = BucketNameGenerator.largeWordlistSize();
        BucketNameGenerator.LargeWordlistBatch first = BucketNameGenerator.generateFromLargeWordlist("acme.com", 100, 50);
        assertThat(first.nextOffset()).isEqualTo(150 % total);

        BucketNameGenerator.LargeWordlistBatch second =
                BucketNameGenerator.generateFromLargeWordlist("acme.com", first.nextOffset(), 50);
        assertThat(second.nextOffset()).isEqualTo(200 % total);
    }

    @Test
    void generateFromLargeWordlist_wrapsAroundAtEndOfWordlist() {
        int total = BucketNameGenerator.largeWordlistSize();
        BucketNameGenerator.LargeWordlistBatch batch = BucketNameGenerator.generateFromLargeWordlist("acme.com", total - 2, 5);

        // Took terms at indices total-2, total-1, 0, 1, 2 - wrapped around rather than stopping at the end.
        assertThat(batch.nextOffset()).isEqualTo(3);
    }

    @Test
    void generateFromLargeWordlist_zeroBatchSize_yieldsNoCandidates_offsetUnchanged() {
        BucketNameGenerator.LargeWordlistBatch batch = BucketNameGenerator.generateFromLargeWordlist("acme.com", 42, 0);

        assertThat(batch.candidates()).isEmpty();
        assertThat(batch.nextOffset()).isEqualTo(42);
    }

    @Test
    void generateFromLargeWordlist_tooShortStem_yieldsNoCandidates() {
        BucketNameGenerator.LargeWordlistBatch batch = BucketNameGenerator.generateFromLargeWordlist("a.com", 0, 10);

        assertThat(batch.candidates()).isEmpty();
    }

    @Test
    void generateAzureAccountCandidates_strippedOfHyphens_unlikeGenerate() {
        // "jaja-co" (the regular generate() stem for jaja.co.uk) is invalid as an Azure storage
        // account name - hyphens aren't allowed at all, unlike S3 bucket names.
        List<String> candidates = BucketNameGenerator.generateAzureAccountCandidates("jaja.co.uk");

        assertThat(candidates).contains("jajaco");
        assertThat(candidates).allSatisfy(c -> assertThat(c).matches("[a-z0-9]+"));
    }

    @Test
    void generateAzureAccountCandidates_cappedAtAzuresOwn24CharLimit() {
        List<String> candidates = BucketNameGenerator.generateAzureAccountCandidates("acme.com");

        assertThat(candidates).allSatisfy(c -> assertThat(c.length()).isLessThanOrEqualTo(24));
    }

    @Test
    void generateAzureAccountCandidates_muchSmallerThanTheFullWordlistCrossProduct() {
        // Deliberately scoped down (see the method's own javadoc) - not the ~400-candidate range
        // generate() produces, since Azure crosses this list against container names too.
        List<String> candidates = BucketNameGenerator.generateAzureAccountCandidates("acme.com");

        assertThat(candidates.size()).isLessThan(30);
    }

    @Test
    void generateAzureAccountCandidates_tooShortStem_yieldsNoCandidates() {
        assertThat(BucketNameGenerator.generateAzureAccountCandidates("a.com")).isEmpty();
    }

    @Test
    void generateAzureAccountCandidates_nullHostname_yieldsNoCandidates() {
        assertThat(BucketNameGenerator.generateAzureAccountCandidates(null)).isEmpty();
    }

    @Test
    void azureContainerNames_includesTheReservedStaticWebsiteContainer() {
        // "$web" isn't a guess - it's Azure's own fixed, reserved container name for static
        // website hosting, used verbatim by any account with that feature enabled.
        assertThat(BucketNameGenerator.AZURE_CONTAINER_NAMES).contains("$web");
    }
}
