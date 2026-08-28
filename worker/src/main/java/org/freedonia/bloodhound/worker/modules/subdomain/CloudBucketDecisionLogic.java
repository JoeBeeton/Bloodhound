package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.Optional;

/**
 * Pure decision logic for cloud-storage-bucket public-listing exposure -
 * distinct from {@link DanglingCnameDecisionLogic}, which answers "is this
 * bucket unclaimed" (a takeover risk); this answers "is this bucket claimed
 * by the target AND readable by anyone" (a data-exposure risk). Same
 * underlying resource type, two genuinely different findings.
 *
 * <p>{@link #matchProvider} is CNAME-based discovery only (a subdomain
 * aliased directly to a bucket via DNS - the "passive DNS correlation" the
 * original design called for), deliberately not brute-forced. {@link
 * #directBucketUrl} is the brute-force counterpart added for the Tier 2
 * {@code BUCKET_BRUTE_FORCE} module (see worker's {@code bucketbrute}
 * package) - given a *guessed* candidate name rather than a discovered
 * CNAME, so it's public (not package-private like this class used to be)
 * for cross-package reuse. {@link #isPubliclyListable} is shared by both
 * discovery paths unchanged - the actual "is it public" check is identical
 * either way.
 *
 * <p>{@link #matchProvider} covers AWS S3 and Google Cloud Storage only, not
 * Azure Blob Storage: S3 and GCS's CNAME setups both identify the specific
 * bucket (S3 encodes it directly in the CNAME target itself; GCS's
 * custom-domain convention requires the bucket to be *named* after the
 * custom domain, so the original hostname doubles as the bucket name).
 * Azure's custom-domain mapping is at the storage-*account* level - the
 * CNAME target alone never identifies which container to check, and
 * guessing container names would cross into the brute-forcing this specific
 * method deliberately avoids. A real, documented gap, not an oversight.
 * {@link #directBucketUrl} covers three more providers on top of S3/GCS
 * (DigitalOcean Spaces, Linode, Scaleway) since brute-force naturally lifts
 * the CNAME-derivability constraint that limited passive discovery - each
 * checked against one representative/default region only (a scoped
 * limitation, not full multi-region coverage).
 */
public final class CloudBucketDecisionLogic {

    public enum Provider {
        AWS_S3,
        GCS,
        DIGITALOCEAN_SPACES,
        LINODE,
        SCALEWAY
    }

    record Match(Provider provider, String checkUrl) {}

    /** Both S3 and GCS's public/no-auth listing responses share this exact root element - GCS's XML API deliberately mimics S3's for compatibility, confirmed public knowledge from both providers' own docs. DigitalOcean Spaces, Linode Object Storage, and Scaleway Object Storage all implement the S3 API directly, so they share it too. */
    private static final String LISTING_MARKER = "<ListBucketResult";

    private CloudBucketDecisionLogic() {}

    /**
     * The brute-force counterpart to {@link #matchProvider}: given a
     * candidate bucket *name* (not a discovered CNAME), the URL to check for
     * public listability on the given provider. One fixed, representative
     * region per non-S3/GCS provider (DigitalOcean: nyc3, Linode: us-east-1,
     * Scaleway: fr-par) - checking every region each provider offers would
     * multiply request volume for marginal extra coverage; documented scoped
     * limitation, same precedent as {@link #matchProvider}'s Azure gap.
     */
    public static String directBucketUrl(Provider provider, String bucketName) {
        return switch (provider) {
            case AWS_S3 -> "https://" + bucketName + ".s3.amazonaws.com/";
            case GCS -> "https://storage.googleapis.com/" + bucketName;
            case DIGITALOCEAN_SPACES -> "https://" + bucketName + ".nyc3.digitaloceanspaces.com/";
            case LINODE -> "https://" + bucketName + ".us-east-1.linodeobjects.com/";
            case SCALEWAY -> "https://" + bucketName + ".s3.fr-par.scw.cloud/";
        };
    }

    /** The shared provider hostname brute-force checks against {@code provider} should be
     * rate-limited by - NOT the per-candidate hostname {@link #directBucketUrl} builds, since
     * hundreds of distinct candidate hostnames all resolve to the same handful of shared
     * provider edge networks. Rate-limiting per-candidate would let a scan technically satisfy
     * a per-hostname limiter while still bursting far more traffic at one provider than
     * intended. See worker's {@code bucketbrute.BucketBruteForceModule}. */
    public static String rateLimitKeyFor(Provider provider) {
        return switch (provider) {
            case AWS_S3 -> "s3.amazonaws.com";
            case GCS -> "storage.googleapis.com";
            case DIGITALOCEAN_SPACES -> "digitaloceanspaces.com";
            case LINODE -> "linodeobjects.com";
            case SCALEWAY -> "scw.cloud";
        };
    }

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

    public static boolean isPubliclyListable(int statusCode, String responseBody) {
        return statusCode == 200 && responseBody != null && responseBody.contains(LISTING_MARKER);
    }
}
