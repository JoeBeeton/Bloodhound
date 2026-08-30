package org.freedonia.bloodhound.server.findings;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.junit.jupiter.api.Test;

class FindingCsvWriterTest {

    private static FindingSummary summary(String title, String description) {
        return new FindingSummary(
                java.util.UUID.randomUUID(),
                "bh-test-1",
                java.util.UUID.randomUUID(),
                "HTTP",
                "RULE_X",
                "HIGH",
                "EXPOSURE",
                title,
                description,
                Map.of(),
                "asset.example.com",
                java.util.UUID.randomUUID(),
                "OPEN",
                null,
                Instant.now(),
                Instant.now(),
                Instant.now(),
                Instant.now(),
                "fix it",
                null);
    }

    private static OrgFindingSummary orgSummary(String targetHostname, String title) {
        return new OrgFindingSummary(
                java.util.UUID.randomUUID(),
                "bh-test-1",
                java.util.UUID.randomUUID(),
                targetHostname,
                "HTTP",
                "RULE_X",
                "HIGH",
                "EXPOSURE",
                title,
                "some description",
                Map.of(),
                "asset.example.com",
                java.util.UUID.randomUUID(),
                "OPEN",
                null,
                Instant.now(),
                Instant.now(),
                Instant.now(),
                Instant.now(),
                "fix it",
                null);
    }

    @Test
    void write_headerRowFirst() {
        String csv = FindingCsvWriter.write(List.of());

        assertThat(csv).isEqualTo("Display ID,Severity,Category,Rule ID,Title,Description,Affected Asset,"
                + "Status,First Seen,Last Seen,Resolved At,Remediation Advice\r\n");
    }

    @Test
    void write_plainFields_noQuoting() {
        String csv = FindingCsvWriter.write(List.of(summary("Open port", "Port 22 is open")));

        assertThat(csv).contains("bh-test-1,HIGH,EXPOSURE,RULE_X,Open port,Port 22 is open,asset.example.com,OPEN");
    }

    @Test
    void escape_null_becomesEmptyString() {
        assertThat(FindingCsvWriter.escape(null)).isEmpty();
    }

    @Test
    void escape_fieldWithComma_quoted() {
        assertThat(FindingCsvWriter.escape("a, b")).isEqualTo("\"a, b\"");
    }

    @Test
    void escape_fieldWithEmbeddedQuote_quotedAndDoubled() {
        assertThat(FindingCsvWriter.escape("say \"hi\"")).isEqualTo("\"say \"\"hi\"\"\"");
    }

    @Test
    void escape_fieldWithNewline_quoted() {
        assertThat(FindingCsvWriter.escape("line1\nline2")).isEqualTo("\"line1\nline2\"");
    }

    @Test
    void escape_formulaInjectionAttempt_prefixedWithApostrophe() {
        // Finding titles/descriptions are attacker-influenced (e.g. a ZAP alert reflecting a
        // scanned page's own content) - a leading =, +, -, @, tab, or CR would otherwise be
        // interpreted as a formula by Excel/Sheets when the exported file is opened.
        assertThat(FindingCsvWriter.escape("=cmd|'/c calc'!A1")).isEqualTo("'=cmd|'/c calc'!A1");
        assertThat(FindingCsvWriter.escape("+1+1")).startsWith("'+");
        assertThat(FindingCsvWriter.escape("-1+1")).startsWith("'-");
        // Also contains a comma, so both guards apply: apostrophe-prefixed, then RFC 4180 quoted.
        assertThat(FindingCsvWriter.escape("@SUM(1,2)")).isEqualTo("\"'@SUM(1,2)\"");
    }

    @Test
    void escape_ordinaryTextStartingWithHyphen_stillGuarded() {
        // Even an innocuous-looking "-day-old finding" title gets the guard - there's no reliable
        // way to distinguish "meant as a formula" from "just starts with a hyphen" from here, so
        // this deliberately errs toward always neutralizing a leading formula-trigger character.
        assertThat(FindingCsvWriter.escape("-3 days ago")).isEqualTo("'-3 days ago");
    }

    @Test
    void escape_formulaCharacterMidString_notPrefixed() {
        assertThat(FindingCsvWriter.escape("total=5")).isEqualTo("total=5");
    }

    @Test
    void writeOrgWide_headerRowFirst_leadingTargetColumn() {
        String csv = FindingCsvWriter.writeOrgWide(List.of());

        assertThat(csv).isEqualTo("Target,Display ID,Severity,Category,Rule ID,Title,Description,Affected Asset,"
                + "Status,First Seen,Last Seen,Resolved At,Remediation Advice\r\n");
    }

    @Test
    void writeOrgWide_multipleTargets_eachRowCarriesItsOwnHostname() {
        // The whole point of the org-wide variant - a row with no target context is meaningless
        // once findings span more than one target.
        String csv = FindingCsvWriter.writeOrgWide(
                List.of(orgSummary("a.example.com", "Finding on A"), orgSummary("b.example.com", "Finding on B")));

        assertThat(csv).contains("a.example.com,bh-test-1,HIGH,EXPOSURE,RULE_X,Finding on A");
        assertThat(csv).contains("b.example.com,bh-test-1,HIGH,EXPOSURE,RULE_X,Finding on B");
    }
}
