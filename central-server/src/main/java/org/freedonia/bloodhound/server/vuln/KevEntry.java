package org.freedonia.bloodhound.server.vuln;

import java.time.LocalDate;

/** One row from CISA's Known Exploited Vulnerabilities catalog. */
public record KevEntry(
        String cveId, String vendorProject, String product, String vulnerabilityName, LocalDate dateAdded) {}
