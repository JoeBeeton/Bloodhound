package org.freedonia.bloodhound.server.vuln;

import java.time.Instant;

/** One CVE's human-readable description, as returned by osv.dev. {@code description} is null when OSV has no entry for this CVE at all (expected - OSV's dataset skews open-source, not every CVE is covered). */
public record OsvCveDetail(String cveId, String description, String severity, Instant publishedDate) {}
