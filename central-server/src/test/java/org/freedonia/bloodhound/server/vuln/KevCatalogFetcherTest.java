package org.freedonia.bloodhound.server.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Parser-only tests against a canned CISA KEV feed fixture (real shape, captured from the live feed during development) - zero network calls. */
class KevCatalogFetcherTest {

    private final KevCatalogFetcher fetcher = new KevCatalogFetcher();

    @Test
    void parsesRealShapedFeed() {
        String json = """
                {
                  "title": "CISA Catalog of Known Exploited Vulnerabilities",
                  "catalogVersion": "2026.08.21",
                  "dateReleased": "2026-08-21T00:00:00.0000Z",
                  "count": 2,
                  "vulnerabilities": [
                    {
                      "cveID": "CVE-2026-73570",
                      "vendorProject": "Synacor",
                      "product": "Zimbra Collaboration Suite (ZCS)",
                      "vulnerabilityName": "Zimbra Collaboration Suite (ZCS) OS Command Injection Vulnerability",
                      "dateAdded": "2026-08-21",
                      "shortDescription": "..."
                    },
                    {
                      "cveID": "CVE-2023-44487",
                      "vendorProject": "Multiple",
                      "product": "Multiple HTTP/2 Implementations",
                      "vulnerabilityName": "HTTP/2 Rapid Reset Attack",
                      "dateAdded": "2023-10-19"
                    }
                  ]
                }
                """;
        List<KevEntry> entries = fetcher.parse(json);
        assertThat(entries).hasSize(2);
        assertThat(entries.get(0).cveId()).isEqualTo("CVE-2026-73570");
        assertThat(entries.get(0).vendorProject()).isEqualTo("Synacor");
        assertThat(entries.get(0).dateAdded()).isEqualTo(LocalDate.of(2026, 8, 21));
        assertThat(entries.get(1).cveId()).isEqualTo("CVE-2023-44487");
    }

    @Test
    void entryMissingCveId_isSkippedNotThrown() {
        String json = """
                {"vulnerabilities": [{"vendorProject": "NoCveHere"}, {"cveID": "CVE-2024-0001"}]}
                """;
        List<KevEntry> entries = fetcher.parse(json);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).cveId()).isEqualTo("CVE-2024-0001");
    }

    @Test
    void malformedDateAdded_leavesDateNullRatherThanThrowing() {
        String json = """
                {"vulnerabilities": [{"cveID": "CVE-2024-0002", "dateAdded": "not-a-date"}]}
                """;
        List<KevEntry> entries = fetcher.parse(json);
        assertThat(entries.get(0).dateAdded()).isNull();
    }

    @Test
    void malformedJson_producesEmptyListNotException() {
        assertThat(fetcher.parse("{not valid")).isEmpty();
    }

    @Test
    void emptyVulnerabilitiesArray_producesEmptyList() {
        assertThat(fetcher.parse("{\"vulnerabilities\": []}")).isEmpty();
    }
}
