package org.freedonia.bloodhound.worker.modules.nuclei;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class NucleiResultParserTest {

    // Real-shaped nuclei v3.11.1 -jsonl -omit-raw output, captured from a live run.
    private static final String REAL_LINE =
            "{\"template\":\"http/technologies/apache/apache-detect.yaml\",\"template-url\":\"https://cloud.projectdiscovery.io/public/apache-detect\","
                    + "\"template-id\":\"apache-detect\",\"template-path\":\"/opt/nuclei-templates/http/technologies/apache/apache-detect.yaml\","
                    + "\"info\":{\"name\":\"Apache Detection\",\"author\":[\"philippedelteil\"],\"tags\":[\"tech\",\"apache\",\"discovery\"],"
                    + "\"description\":\"Some Apache servers have the version on the response header.\",\"severity\":\"info\","
                    + "\"reference\":[\"https://example.org/apache-detect\"],\"metadata\":{\"max-request\":1},"
                    + "\"classification\":{\"cve-id\":null,\"cwe-id\":[\"cwe-200\"]}},"
                    + "\"type\":\"http\",\"host\":\"scanme.nmap.org\",\"port\":\"80\",\"scheme\":\"http\","
                    + "\"url\":\"http://scanme.nmap.org\",\"matched-at\":\"http://scanme.nmap.org\","
                    + "\"extracted-results\":[\"Apache/2.4.7 (Ubuntu)\"],\"ip\":\"45.33.32.156\","
                    + "\"timestamp\":\"2026-08-26T15:44:12.398Z\","
                    + "\"curl-command\":\"curl -X 'GET' 'http://scanme.nmap.org'\",\"matcher-status\":true}";

    @Test
    void nullOrBlankJsonl_emptyList() {
        assertThat(NucleiResultParser.parse(null)).isEmpty();
        assertThat(NucleiResultParser.parse("")).isEmpty();
        assertThat(NucleiResultParser.parse("   ")).isEmpty();
    }

    @Test
    void realShapedLine_parsedCorrectly() {
        List<NucleiFinding> results = NucleiResultParser.parse(REAL_LINE);
        assertThat(results).hasSize(1);
        NucleiFinding finding = results.get(0);
        assertThat(finding.templateId()).isEqualTo("apache-detect");
        assertThat(finding.name()).isEqualTo("Apache Detection");
        assertThat(finding.severity()).isEqualTo("info");
        assertThat(finding.description()).isEqualTo("Some Apache servers have the version on the response header.");
        assertThat(finding.host()).isEqualTo("scanme.nmap.org");
        assertThat(finding.matchedAt()).isEqualTo("http://scanme.nmap.org");
        assertThat(finding.reference()).isEqualTo("https://example.org/apache-detect");
        assertThat(finding.extractedResults()).containsExactly("Apache/2.4.7 (Ubuntu)");
        assertThat(finding.curlCommand()).isEqualTo("curl -X 'GET' 'http://scanme.nmap.org'");
        assertThat(finding.cveId()).isNull();
    }

    @Test
    void multipleLines_allParsed() {
        String jsonl = REAL_LINE + "\n" + REAL_LINE.replace("apache-detect", "nginx-detect");
        assertThat(NucleiResultParser.parse(jsonl)).hasSize(2);
    }

    @Test
    void blankLinesBetweenResults_skipped() {
        String jsonl = REAL_LINE + "\n\n\n" + REAL_LINE.replace("apache-detect", "nginx-detect");
        assertThat(NucleiResultParser.parse(jsonl)).hasSize(2);
    }

    @Test
    void strayNonJsonLine_skippedDefensively() {
        String jsonl = "not valid json at all\n" + REAL_LINE;
        assertThat(NucleiResultParser.parse(jsonl)).hasSize(1);
    }

    @Test
    void missingOptionalFields_nullsNotExceptions() {
        String minimal = "{\"template-id\":\"minimal-check\",\"info\":{\"severity\":\"low\"}}";
        List<NucleiFinding> results = NucleiResultParser.parse(minimal);
        assertThat(results).hasSize(1);
        NucleiFinding finding = results.get(0);
        assertThat(finding.templateId()).isEqualTo("minimal-check");
        assertThat(finding.name()).isNull();
        assertThat(finding.severity()).isEqualTo("low");
        assertThat(finding.matchedAt()).isNull();
        assertThat(finding.reference()).isNull();
        assertThat(finding.extractedResults()).isEmpty();
        assertThat(finding.cveId()).isNull();
    }

    @Test
    void cveClassification_extracted() {
        String withCve = "{\"template-id\":\"cve-2021-12345\",\"info\":{\"severity\":\"critical\","
                + "\"classification\":{\"cve-id\":\"CVE-2021-12345\"}}}";
        List<NucleiFinding> results = NucleiResultParser.parse(withCve);
        assertThat(results.get(0).cveId()).isEqualTo("CVE-2021-12345");
    }

    @Test
    void multipleReferences_joined() {
        String multiRef = "{\"template-id\":\"t\",\"info\":{\"severity\":\"info\","
                + "\"reference\":[\"https://a.example\",\"https://b.example\"]}}";
        List<NucleiFinding> results = NucleiResultParser.parse(multiRef);
        assertThat(results.get(0).reference()).isEqualTo("https://a.example, https://b.example");
    }

    /** Captured from a live run of nuclei's own waf-detect template against a real Cloudflare-fronted host. */
    @Test
    void matcherName_extractedFromRealWafDetectLine() {
        String wafDetectLine = "{\"template-id\":\"waf-detect\",\"info\":{\"name\":\"WAF Detection\",\"severity\":\"info\"},"
                + "\"matcher-name\":\"cloudflare\",\"host\":\"asda.jaja.co.uk\",\"matched-at\":\"https://asda.jaja.co.uk\"}";
        List<NucleiFinding> results = NucleiResultParser.parse(wafDetectLine);
        assertThat(results.get(0).matcherName()).isEqualTo("cloudflare");
    }

    @Test
    void missingMatcherName_null() {
        assertThat(NucleiResultParser.parse(REAL_LINE).get(0).matcherName()).isNull();
    }
}
