package org.freedonia.bloodhound.server.eol;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Pure matching of a fingerprinted version string against a product's cached release
 * cycles - no I/O, fully unit-testable. The one genuinely new piece of logic this
 * feature needs; nothing in {@code vuln} has an analogue, since CVE correlation matches
 * on an exact (technology, version) pair rather than a version-to-cycle relationship.
 *
 * <p>endoflife.date releases are cataloged by cycle (e.g. nginx's "1.24"), not by every
 * individual patch version - a fingerprinted "1.24.3" belongs to cycle "1.24" because
 * its leading dot-separated segments equal the cycle's own segments. Compared
 * segment-by-segment (not a raw string prefix) so cycle "1.2" does NOT match version
 * "1.24.3" (second segment "2" != "24") even though "1.2" is a raw string prefix of
 * "1.24.3".
 */
public final class EolVersionMatcher {

    private EolVersionMatcher() {}

    /** The release cycle {@code version} belongs to, or empty if it doesn't fall under any cached cycle (e.g. a version newer than anything endoflife.date has cataloged yet) - "not evaluated", never "flagged" for an unmatched version. If more than one cycle's segments are a match, the most specific (most segments) wins. */
    public static Optional<EolRelease> match(String version, List<EolRelease> releases) {
        if (version == null || version.isBlank()) {
            return Optional.empty();
        }
        List<String> versionSegments = List.of(version.split("\\."));
        return releases.stream()
                .filter(r -> cycleMatches(versionSegments, r.releaseCycle()))
                .max(Comparator.comparingInt(r -> r.releaseCycle().split("\\.").length));
    }

    private static boolean cycleMatches(List<String> versionSegments, String releaseCycle) {
        String[] cycleSegments = releaseCycle.split("\\.");
        if (cycleSegments.length > versionSegments.size()) {
            return false;
        }
        for (int i = 0; i < cycleSegments.length; i++) {
            if (!cycleSegments[i].equals(versionSegments.get(i))) {
                return false;
            }
        }
        return true;
    }
}
