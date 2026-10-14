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

    /** The real, live-captured response shape from a genuinely public Azure storage account (Microsoft's own azureopendatastorage/nyctlc). */
    @Test
    void publiclyListable_azureEnumerationResultsMarker_alsoRecognized() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(
                        200,
                        "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults "
                                + "ServiceEndpoint=\"https://acme.blob.core.windows.net/\" "
                                + "ContainerName=\"public\"><Blobs>...</Blobs></EnumerationResults>"))
                .isTrue();
    }

    /** The real, live-captured response shape for a private/nonexistent container on a real Azure account. */
    @Test
    void azureNoAuthError_notListable() {
        assertThat(CloudBucketDecisionLogic.isPubliclyListable(
                        401, "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>NoAuthenticationInformation</Code></Error>"))
                .isFalse();
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

    @Test
    void directBucketUrl_buildsCorrectEndpointPerProvider() {
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.AWS_S3, "acme-backup"))
                .isEqualTo("https://acme-backup.s3.amazonaws.com/");
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.GCS, "acme-backup"))
                .isEqualTo("https://storage.googleapis.com/acme-backup");
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.DIGITALOCEAN_SPACES, "acme-backup"))
                .isEqualTo("https://acme-backup.nyc3.digitaloceanspaces.com/");
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.LINODE, "acme-backup"))
                .isEqualTo("https://acme-backup.us-east-1.linodeobjects.com/");
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.SCALEWAY, "acme-backup"))
                .isEqualTo("https://acme-backup.s3.fr-par.scw.cloud/");
    }

    @Test
    void directBucketUrl_azure_splitsCompoundAccountSlashContainerName() {
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.AZURE_BLOB, "acme/public"))
                .isEqualTo("https://acme.blob.core.windows.net/public?restype=container&comp=list&maxresults=1");
    }

    /** No slash in the candidate (shouldn't happen given how BucketBruteForceModule always builds it) falls back to "$web" rather than throwing. */
    @Test
    void directBucketUrl_azure_missingSlash_fallsBackToWebContainer() {
        assertThat(CloudBucketDecisionLogic.directBucketUrl(CloudBucketDecisionLogic.Provider.AZURE_BLOB, "acme"))
                .isEqualTo("https://acme.blob.core.windows.net/$web?restype=container&comp=list&maxresults=1");
    }

    @Test
    void rateLimitKeyFor_isTheSharedProviderHost_notThePerCandidateHostname() {
        // Every candidate resolves to a distinct hostname on the same shared provider
        // infrastructure - the rate-limit key must be the provider host, not the candidate's
        // own generated hostname, or a brute-force run could burst far more traffic at one
        // provider than a per-hostname limiter would ever catch.
        assertThat(CloudBucketDecisionLogic.rateLimitKeyFor(CloudBucketDecisionLogic.Provider.AWS_S3))
                .isEqualTo("s3.amazonaws.com");
        assertThat(CloudBucketDecisionLogic.rateLimitKeyFor(CloudBucketDecisionLogic.Provider.GCS))
                .isEqualTo("storage.googleapis.com");
        assertThat(CloudBucketDecisionLogic.rateLimitKeyFor(CloudBucketDecisionLogic.Provider.AZURE_BLOB))
                .isEqualTo("blob.core.windows.net");
    }
}
