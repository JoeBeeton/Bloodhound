package org.freedonia.bloodhound.worker.modules.bucketbrute;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
     * predictable. Sized to land comfortably in the 200-500 range SMALL_WORDLIST produces. */
    private static final int MAX_CANDIDATES = 400;

    /**
     * CloudBrute's own storage-name wordlists (MIT-licensed - see NOTICE), bundled as classpath
     * resources rather than a hand-rolled list: a purpose-built, community-maintained corpus of
     * real bucket-naming conventions beats guessing our own. SMALL (112 terms) replaces what used
     * to be an inline hardcoded list, at the same ~200-500-candidate scale every deep scan already
     * budgets for. LARGE (18,696 terms, sanitized to bucket-name-safe characters - the upstream
     * file also mixes in web-content-discovery terms like "Contact Us"/"~admin" that can never be
     * a valid bucket name) is FAR too big to check in one run; see {@link #generateFromLargeWordlist}
     * for how a deep scan instead works through it incrementally across many runs.
     */
    private static final List<String> SMALL_WORDLIST = loadWordlist("/wordlists/cloudbrute-storage-small.txt");

    private static final List<String> LARGE_WORDLIST = loadWordlist("/wordlists/cloudbrute-storage-large.txt");

    /** Smaller prefix set - a prefix reads more naturally for a handful of these than every
     * suffix would as a prefix too, so kept separate rather than reusing SMALL_WORDLIST both ways. */
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
        for (String suffix : SMALL_WORDLIST) {
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

    /** One incremental slice through {@link #LARGE_WORDLIST}, plus where the next slice should
     * pick up - see {@link #generateFromLargeWordlist}. */
    record LargeWordlistBatch(List<String> candidates, int nextOffset) {}

    /**
     * The resumable counterpart to {@link #generate}: rather than the ~200-500 candidates that
     * fit in one scan's budget, {@link #LARGE_WORDLIST} has 18,696 terms - crossed with a stem and
     * checked across 5 providers, that's ~187,000 requests, hours even at a healthy rate limit.
     * Central-server persists a per-target cursor (see BucketBruteForceCursorRepository) and hands
     * this module a starting {@code offset} plus how many terms to take (see
     * ScanRunService#targetScopedPayload); this module reports back {@link
     * LargeWordlistBatch#nextOffset} for central-server to save for next time. Wraps around at the
     * end of the list (via floorMod) rather than stopping, so a target's coverage keeps growing
     * across every deep scan indefinitely, revisiting the start once a full pass completes - by
     * then names once absent from the list may have appeared upstream, or the target's own stem
     * may have changed.
     */
    static LargeWordlistBatch generateFromLargeWordlist(String rootHostname, int offset, int batchSize) {
        String stem = sanitizedStem(rootHostname);
        if (stem == null || batchSize <= 0 || LARGE_WORDLIST.isEmpty()) {
            return new LargeWordlistBatch(List.of(), offset);
        }
        int total = LARGE_WORDLIST.size();
        int start = Math.floorMod(offset, total);
        Set<String> candidates = new LinkedHashSet<>();
        for (int i = 0; i < batchSize; i++) {
            String term = LARGE_WORDLIST.get((start + i) % total);
            candidates.add(stem + "-" + term);
            candidates.add(stem + term);
        }
        int nextOffset = (start + batchSize) % total;
        return new LargeWordlistBatch(new ArrayList<>(candidates), nextOffset);
    }

    /** Test-only visibility into the large wordlist's real size, so tests can exercise wraparound
     * behavior without hardcoding a count that would silently drift if the bundled resource changes. */
    static int largeWordlistSize() {
        return LARGE_WORDLIST.size();
    }

    /**
     * Common Azure Blob Storage container names - a different naming convention entirely from the
     * bucket-name wordlists above: container names are short and often generic, and "$web"
     * specifically is Azure's own fixed, reserved container name for static-website hosting (not
     * a guess at all - any storage account with that feature enabled uses exactly this name).
     */
    static final List<String> AZURE_CONTAINER_NAMES = List.of(
            "$web", "public", "backup", "backups", "data", "files", "uploads", "images", "assets", "media",
            "documents", "static", "container1");

    /**
     * Azure needs an account-name guess AND a container-name guess crossed together (see
     * CloudBucketDecisionLogic's own javadoc on why passive CNAME-based discovery can't identify
     * Azure containers at all) - keeping this side of the cross-product close to brand-exact
     * variants, not the full ~400-candidate {@link #generate} list, keeps total request volume for
     * this one extra provider proportionate to what the other five already budget for combined
     * (see BucketBruteForceModule's own OVERALL_BUDGET reasoning).
     *
     * <p>Azure storage account names are stricter than S3 bucket names: lowercase letters and
     * digits only (no hyphens), 3-24 characters - {@link #sanitizedStem} allows hyphens (needed
     * for multi-label domains like "jaja.co.uk" -> "jaja-co"), so hyphens are stripped again here
     * specifically for this candidate set.
     */
    static List<String> generateAzureAccountCandidates(String rootHostname) {
        String stem = sanitizedStem(rootHostname);
        if (stem == null) {
            return List.of();
        }
        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(azureSafe(stem));
        for (String prefix : PREFIXES) {
            candidates.add(azureSafe(prefix + stem));
        }
        for (String year : YEARS) {
            candidates.add(azureSafe(stem + year));
        }
        candidates.removeIf(c -> c.length() < 3);
        return new ArrayList<>(candidates);
    }

    private static final int AZURE_ACCOUNT_NAME_MAX_LENGTH = 24;

    private static String azureSafe(String candidate) {
        String stripped = candidate.replace("-", "");
        return stripped.length() > AZURE_ACCOUNT_NAME_MAX_LENGTH
                ? stripped.substring(0, AZURE_ACCOUNT_NAME_MAX_LENGTH)
                : stripped;
    }

    /** Tolerant of a missing resource (returns empty, same "degrade, don't fail the module"
     * philosophy as the rest of this class) - the classpath resource not being found would mean a
     * packaging bug, not a runtime condition worth throwing over. */
    private static List<String> loadWordlist(String resourcePath) {
        try (InputStream is = BucketNameGenerator.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                return List.of();
            }
            List<String> lines = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    lines.add(trimmed);
                }
            }
            return List.copyOf(lines);
        } catch (IOException e) {
            return List.of();
        }
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
