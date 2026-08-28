package org.freedonia.bloodhound.worker.modules.bucketbrute;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Generates candidate cloud-storage bucket names for a target's own root
 * hostname - the brute-force counterpart to {@link
 * org.freedonia.bloodhound.worker.modules.typosquat.PermutationGenerator},
 * same "bounded, deterministic, capped" shape. Domain splitting is the same
 * simple last-dot split {@code PermutationGenerator}/{@code
 * WhoisFetcher.tldOf()} already use elsewhere in this codebase - a full
 * public-suffix-list-aware split (to correctly isolate the brand label from
 * multi-part TLDs like co.uk) is a known, shared limitation, not solved
 * here. For "jaja.co.uk" this yields the sanitized stem "jaja-co", not
 * "jaja" - candidates built from it are still plausible bucket-naming
 * conventions, just not maximally precise for multi-part TLDs.
 */
final class BucketNameGenerator {

    /** Bounds total output regardless of stem length - keeps per-scan request volume
     * predictable. Sized to land comfortably in the 200-500 range the wordlist below produces. */
    private static final int MAX_CANDIDATES = 400;

    /** Common bucket-naming conventions - environment/lifecycle, content-type, and
     * infrastructure-role terms real organizations actually use for cloud storage buckets. */
    private static final List<String> SUFFIXES = List.of(
            "backup", "backups", "prod", "production", "dev", "development", "staging", "stage", "test",
            "testing", "uat", "qa", "assets", "static", "media", "images", "img", "files", "uploads",
            "downloads", "data", "database", "db", "logs", "log", "archive", "archives", "temp", "tmp",
            "cache", "cdn", "public", "private", "internal", "secure", "admin", "api", "www", "web", "app",
            "apps", "mobile", "docs", "documents", "reports", "exports", "imports", "config", "secrets",
            "keys", "source", "src", "build", "dist", "release", "deploy", "terraform", "infra", "ops",
            "monitoring", "analytics", "marketing", "sales", "finance", "billing", "content", "storage",
            "bucket", "share", "shared", "old", "new", "legacy", "migration", "sandbox", "demo", "training",
            "hr", "legal", "corp", "us", "eu", "prod-data", "user-data", "customer-data");

    /** Smaller prefix set - a prefix reads more naturally for a handful of these than every
     * suffix would as a prefix too, so kept separate rather than reusing SUFFIXES both ways. */
    private static final List<String> PREFIXES =
            List.of("www", "dev", "prod", "staging", "backup", "old", "new", "legacy", "static", "cdn", "assets");

    /** Year/index suffixes - genuinely common for backup/archive/versioned buckets
     * ("acme-backup-2025", "acme-data-01"), not arbitrary padding. */
    private static final List<String> YEARS = List.of("2023", "2024", "2025", "2026");
    private static final List<String> INDICES = List.of("01", "02", "1", "2");

    private BucketNameGenerator() {}

    static List<String> generate(String rootHostname) {
        String stem = sanitizedStem(rootHostname);
        if (stem == null) {
            return List.of();
        }

        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(stem);
        for (String suffix : SUFFIXES) {
            candidates.add(stem + "-" + suffix);
            candidates.add(stem + suffix);
        }
        for (String prefix : PREFIXES) {
            candidates.add(prefix + "-" + stem);
            candidates.add(prefix + stem);
        }
        for (String year : YEARS) {
            candidates.add(stem + "-" + year);
        }
        for (String index : INDICES) {
            candidates.add(stem + "-" + index);
        }

        List<String> result = new ArrayList<>();
        for (String candidate : candidates) {
            if (result.size() >= MAX_CANDIDATES) {
                break;
            }
            result.add(candidate);
        }
        return result;
    }

    /**
     * The root hostname's label (everything before the last dot, same convention {@code
     * PermutationGenerator} uses), lowercased and sanitized to characters real bucket-naming
     * rules actually allow ({@code [a-z0-9-]}, no leading/trailing/duplicate hyphens), and
     * length-bounded the way S3 bucket names must be (3-63 characters) - a stem outside those
     * bounds can never be a real bucket name regardless of what's appended to it, so generating
     * candidates from one would be pure wasted requests.
     */
    private static String sanitizedStem(String rootHostname) {
        if (rootHostname == null) {
            return null;
        }
        int lastDot = rootHostname.lastIndexOf('.');
        String label = (lastDot <= 0 ? rootHostname : rootHostname.substring(0, lastDot)).toLowerCase(Locale.ROOT);
        String sanitized = label.replaceAll("[^a-z0-9-]", "-").replaceAll("-{2,}", "-").replaceAll("^-|-$", "");
        if (sanitized.length() < 3 || sanitized.length() > 40) {
            // Capped below the real 63-char bucket-name limit, not right at it - the longest
            // suffix/prefix combinations below add up to ~20 characters, and a stem sitting
            // right at 63 would push some candidates over the real limit before they're even
            // sanitized further.
            return sanitized.length() < 3 ? null : sanitized.substring(0, 40);
        }
        return sanitized;
    }
}
