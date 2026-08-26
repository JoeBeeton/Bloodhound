package org.freedonia.bloodhound.server.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Parser tests against a real captured osv.dev response (fetched once by hand for CVE-2023-44487, not a live call in this test) and the "OSV has no entry" path. Zero network calls. */
class OsvClientTest {

    private final OsvClient client = new OsvClient();

    // A trimmed but otherwise real capture of GET https://api.osv.dev/v1/vulns/CVE-2023-44487
    private static final String REAL_RESPONSE = """
            {
              "id": "CVE-2023-44487",
              "details": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
              "aliases": ["GHSA-qppj-fm5r-hxr3"],
              "modified": "2026-08-24T08:04:11.147629Z",
              "published": "2023-10-10T00:00:00Z",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
            }
            """;

    @Test
    void parsesRealCaptured2023_44487Response() {
        OsvCveDetail detail = client.parse("CVE-2023-44487", REAL_RESPONSE);

        assertThat(detail.cveId()).isEqualTo("CVE-2023-44487");
        assertThat(detail.description())
                .isEqualTo(
                        "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.");
        assertThat(detail.severity()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
        assertThat(detail.publishedDate()).isEqualTo(Instant.parse("2023-10-10T00:00:00Z"));
    }

    @Test
    void fallsBackToSummary_whenDetailsFieldAbsent() {
        String json = """
                {"id": "CVE-9999-1", "summary": "A short summary only.", "published": "2020-01-01T00:00:00Z"}
                """;
        OsvCveDetail detail = client.parse("CVE-9999-1", json);
        assertThat(detail.description()).isEqualTo("A short summary only.");
    }

    @Test
    void nullRawResponse_meansNoOsvEntry_returnsNullDescriptionNotAnError() {
        // fetchRaw() returns null on a real 404 (confirmed against the live API - a
        // CVE genuinely absent from OSV's mostly-open-source-focused dataset).
        OsvCveDetail detail = client.parse("CVE-0000-00000", null);
        assertThat(detail.description()).isNull();
        assertThat(detail.cveId()).isEqualTo("CVE-0000-00000");
    }

    @Test
    void malformedJson_parsedGracefully_notThrown() {
        OsvCveDetail detail = client.parse("CVE-1234-5678", "{not valid json");
        assertThat(detail.description()).isNull();
    }

    @Test
    void noSeverityArray_leavesSeverityNull() {
        String json = """
                {"id": "CVE-1111-1", "details": "Some description."}
                """;
        OsvCveDetail detail = client.parse("CVE-1111-1", json);
        assertThat(detail.severity()).isNull();
    }
}
