package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class CloudBucketDecisionLogicTest {

    @Test
    void s3VirtualHostedCname_matchesAndUsesCnameTargetDirectly() {
        Optional<CloudBucketDecisionLogic.Match> match =
                CloudBucketDecisionLogic.matchProvider("assets.example.com", "example-assets.s3.amazonaws.com");

        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(CloudBucketDecisionLogic.Provider.AWS_S3);
        assertThat(match.get().checkUrl()).isEqualTo("https://example-assets.s3.amazonaws.com/");
    }

    @Test
    void s3RegionalEndpoint_matches() {
        Optional<CloudBucketDecisionLogic.Match> match = CloudBucketDecisionLogic.matchProvider(
                "downloads.example.com", "example-downloads.s3.eu-west-2.amazonaws.com");

        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(CloudBucketDecisionLogic.Provider.AWS_S3);
    }

    @Test
    void s3WebsiteHostingCname_matches() {
        Optional<CloudBucketDecisionLogic.Match> match = CloudBucketDecisionLogic.matchProvider(
                "static.example.com", "example-static.s3-website-us-east-1.amazonaws.com");

        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(CloudBucketDecisionLogic.Provider.AWS_S3);
    }

    @Test
    void gcsCname_usesOriginalHostnameAsBucketName() {
        // GCS's custom-domain convention: the CNAME target is always the same fixed
        // c.storage.googleapis.com regardless of bucket - the bucket must be *named*
        // after the custom domain itself, so the original hostname is the bucket name.
        Optional<CloudBucketDecisionLogic.Match> match =
                CloudBucketDecisionLogic.matchProvider("cdn.example.com", "c.storage.googleapis.com");

        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(CloudBucketDecisionLogic.Provider.GCS);
        assertThat(match.get().checkUrl()).isEqualTo("https://storage.googleapis.com/cdn.example.com");
    }

    @Test
    void azureBlobCname_deliberatelyNotMatched() {
        // Documented gap: Azure's custom-domain mapping is account-level, not
        // container-level - the CNAME target alone never identifies which container to
        // check, and guessing would cross into brute-forcing.
        Optional<CloudBucketDecisionLogic.Match> match =
                CloudBucketDecisionLogic.matchProvider("files.example.com", "myaccount.blob.core.windows.net");

        assertThat(match).isEmpty();
    }

    @Test
    void unrelatedCname_noMatch() {
        assertThat(CloudBucketDecisionLogic.matchProvider("app.example.com", "myapp.herokuapp.com")).isEmpty();
    }

    @Test
    void nullOrBlankCname_noMatch() {
        assertThat(CloudBucketDecisionLogic.matchProvider("x.example.com", null)).isEmpty();
        assertThat(CloudBucketDecisionLogic.matchProvider("x.example.com", "")).isEmpty();
    }

    @Test
    void publiclyListable_requires200AndListBucketResultMarker() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(200, "<?xml version=\"1.0\"?><ListBucketResult>...</ListBucketResult>"))
                .isTrue();
    }

    @Test
    void accessDenied_notListable() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(403, "<Error><Code>AccessDenied</Code></Error>"))
                .isFalse();
    }

    @Test
    void bucketDoesNotExist_notListable() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(404, "<Error><Code>NoSuchBucket</Code></Error>"))
                .isFalse();
    }

    @Test
    void nullBody_notListable() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(200, null)).isFalse();
    }
}
