package org.freedonia.bloodhound.common.net;

/**
 * The single identifying User-Agent every outbound HTTP request this platform makes - whether
 * to a scan target directly, or to a third party being probed on a target's behalf (e.g. a
 * guessed cloud-storage bucket endpoint) - should carry, so anyone inspecting their own access
 * logs can tell the traffic came from Bloodhound rather than mistaking it for anonymous or
 * malicious scanning.
 *
 * <p>Previously each fetcher hardcoded its own copy of this string inline (nine call sites, one
 * of which - HibpFetcher - had actually drifted to a different suffix, "passive breach
 * correlation" instead of "external attack surface scan") - exactly the kind of thing that
 * silently goes stale across files with no shared source of truth. One constant means every
 * caller stays in sync by construction, and a future rename/version bump only happens once.
 */
public final class ScanUserAgent {

    public static final String VALUE = "Bloodhound-ASM/1.0 (+external attack surface scan)";

    private ScanUserAgent() {}
}
