package org.freedonia.bloodhound.server.vuln;

/** One CVE returned by an NVD lookup, with its highest available CVSS base severity (null if NVD has no CVSS data for it at all - rare but real, mostly very old CVEs). */
public record NvdCveResult(String cveId, String baseSeverity, Double baseScore) {}
