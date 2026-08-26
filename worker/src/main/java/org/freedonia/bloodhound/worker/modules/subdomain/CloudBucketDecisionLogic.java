package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.Optional;

/**
 * Pure decision logic for cloud-storage-bucket public-listing exposure -
 * distinct from {@link DanglingCnameDecisionLogic}, which answers "is this
 * bucket unclaimed" (a takeover risk); this answers "is this bucket claimed
 * by the target AND readable by anyone" (a data-exposure risk). Same
 * underlying resource type, two genuinely different findings.
 *
 * <p>Discovery is CNAME-based only (a subdomain aliased directly to a bucket
 * via DNS - the "passive DNS correlation" the original design called for),
 * deliberately not brute-forced. Scoped to AWS S3 and Google Cloud Storage
 * only, not Azure Blob Storage: S3 and GCS's CNAME setups both identify the
 * specific bucket (S3 encodes it directly in the CNAME target itself; GCS's
 * custom-domain convention requires the bucket to be *named* after the
 * custom domain, so the original hostname doubles as the bucket name).
 * Azure's custom-domain mapping is at the storage-*account* level - the
 * CNAME target alone never identifies which container to check, and
 * guessing container names would cross into the brute-forcing this module
 * deliberately avoids. A real, documented gap, not an oversight.
 */
final class CloudBucketDecisionLogic {

    enum Provider {
        AWS_S3,
        GCS
    }

    record Match(Provider provider, String checkUrl) {}

    /** Both S3 and GCS's public/no-auth listing responses share this exact root element - GCS's XML API deliberately mimics S3's for compatibility, confirmed public knowledge from both providers' own docs. */
    private static final String LISTING_MARKER = "<ListBucketResult";

    private CloudBucketDecisionLogic() {}

    static Optional<Match> matchProvider(String hostname, String cnameTarget) {
        if (cnameTarget == null || cnameTarget.isBlank()) {
            return Optional.empty();
        }
        String lower = cnameTarget.toLowerCase();
        // S3's CNAME target is the bucket's own virtual-hosted-style hostname
        // ("bucket-name.s3.amazonaws.com" or the region-qualified/website-hosting
        // variants) - GET that URL directly, no separate bucket-name derivation needed.
        if (lower.contains(".s3.amazonaws.com") || lower.contains(".s3-website") || lower.matches(".*\\.s3[.-][a-z0-9-]+\\.amazonaws\\.com\\.?")) {
            return Optional.of(new Match(Provider.AWS_S3, "https://" + cnameTarget + "/"));
        }
        // GCS's CNAME target is always the fixed "c.storage.googleapis.com" regardless
        // of bucket - the bucket name comes from the custom domain itself (GCS requires
        // the bucket be named identically to the domain it's mapped to).
        if (lower.contains("storage.googleapis.com")) {
            return Optional.of(new Match(Provider.GCS, "https://storage.googleapis.com/" + hostname));
        }
        return Optional.empty();
    }

    static boolean isPubliclyListable(int statusCode, String responseBody) {
        return statusCode == 200 && responseBody != null && responseBody.contains(LISTING_MARKER);
    }
}
