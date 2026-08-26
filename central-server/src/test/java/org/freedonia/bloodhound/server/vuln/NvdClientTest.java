package org.freedonia.bloodhound.server.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Parser-only tests against canned NVD response fixtures (real shapes, captured from the live API during development) - zero network calls. */
class NvdClientTest {

    private final NvdClient client = new NvdClient();

    @Test
    void parsesCvssV31_preferringItOverV2() {
        // Real shape: a CVE with both cvssMetricV31 and a legacy cvssMetricV2 present -
        // the v3.1 score/severity must win.
        String json = """
                {
                  "vulnerabilities": [
                    {
                      "cve": {
                        "id": "CVE-2021-23017",
                        "metrics": {
                          "cvssMetricV31": [
                            {"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}
                          ],
                          "cvssMetricV2": [
                            {"cvssData": {"baseScore": 6.8}, "baseSeverity": "MEDIUM"}
                          ]
                        }
                      }
                    }
                  ]
                }
                """;
        List<NvdCveResult> results = client.parse(json);
        assertThat(results).hasSize(1);
        assertThat(results.get(0).cveId()).isEqualTo("CVE-2021-23017");
        assertThat(results.get(0).baseSeverity()).isEqualTo("HIGH");
        assertThat(results.get(0).baseScore()).isEqualTo(7.7);
    }

    @Test
    void parsesCvssV2Only_readingBaseSeverityFromParentNodeNotCvssData() {
        // Real, verified-against-the-live-API quirk: CVSS v2's baseSeverity sits
        // alongside cvssData, not inside it (unlike v3.x) - this is the specific case
        // that would silently produce a null severity if that distinction were missed.
        String json = """
                {
                  "vulnerabilities": [
                    {
                      "cve": {
                        "id": "CVE-2009-3896",
                        "metrics": {
                          "cvssMetricV2": [
                            {
                              "cvssData": {"baseScore": 6.8, "version": "2.0"},
                              "baseSeverity": "MEDIUM"
                            }
                          ]
                        }
                      }
                    }
                  ]
                }
                """;
        List<NvdCveResult> results = client.parse(json);
        assertThat(results.get(0).baseSeverity()).isEqualTo("MEDIUM");
        assertThat(results.get(0).baseScore()).isEqualTo(6.8);
    }

    @Test
    void cveWithNoCvssDataAtAll_stillReturnedWithNullSeverity() {
        // Real, rare-but-possible case for very old/unscored CVEs - must not throw.
        String json = """
                {"vulnerabilities": [{"cve": {"id": "CVE-1999-0001", "metrics": {}}}]}
                """;
        List<NvdCveResult> results = client.parse(json);
        assertThat(results).hasSize(1);
        assertThat(results.get(0).cveId()).isEqualTo("CVE-1999-0001");
        assertThat(results.get(0).baseSeverity()).isNull();
        assertThat(results.get(0).baseScore()).isNull();
    }

    @Test
    void emptyVulnerabilitiesArray_producesEmptyList() {
        String json = """
                {"totalResults": 0, "vulnerabilities": []}
                """;
        assertThat(client.parse(json)).isEmpty();
    }

    @Test
    void nullInput_producesEmptyListNotException() {
        // fetchRaw() returns null on a 404 (product not in NVD's CPE dictionary at all) -
        // parse() must handle that gracefully, not NPE.
        assertThat(client.parse(null)).isEmpty();
    }

    @Test
    void malformedJson_producesEmptyListNotException() {
        assertThat(client.parse("{not valid json")).isEmpty();
    }

    @Test
    void multipleVulnerabilities_allParsed() {
        String json = """
                {
                  "vulnerabilities": [
                    {"cve": {"id": "CVE-2021-23017", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}]}}},
                    {"cve": {"id": "CVE-2023-44487", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}}
                  ]
                }
                """;
        List<NvdCveResult> results = client.parse(json);
        assertThat(results).extracting(NvdCveResult::cveId).containsExactly("CVE-2021-23017", "CVE-2023-44487");
    }
}
