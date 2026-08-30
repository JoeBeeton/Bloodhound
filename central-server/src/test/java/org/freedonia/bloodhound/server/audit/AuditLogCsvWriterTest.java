package org.freedonia.bloodhound.server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuditLogCsvWriterTest {

    private static AuditLogEntry entry(String actorEmail, String action, String detail) {
        return new AuditLogEntry(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                actorEmail,
                action,
                "TARGET",
                "target-1",
                detail,
                Instant.parse("2026-01-01T00:00:00Z"));
    }

    @Test
    void write_headerRowFirst() {
        String csv = AuditLogCsvWriter.write(List.of());

        assertThat(csv).isEqualTo("When,Actor,Action,Target Type,Target ID,Detail\r\n");
    }

    @Test
    void write_plainFields_noQuoting() {
        String csv = AuditLogCsvWriter.write(
                List.of(entry("admin@example.com", "TARGET_DELETED", "hostname=example.com")));

        assertThat(csv)
                .contains("2026-01-01T00:00:00Z,admin@example.com,TARGET_DELETED,TARGET,target-1,hostname=example.com");
    }

    @Test
    void write_nullDetail_becomesEmptyField() {
        String csv = AuditLogCsvWriter.write(List.of(entry("admin@example.com", "RULE_ENABLED", null)));

        assertThat(csv).contains("2026-01-01T00:00:00Z,admin@example.com,RULE_ENABLED,TARGET,target-1,\r\n");
    }

    @Test
    void escape_null_becomesEmptyString() {
        assertThat(AuditLogCsvWriter.escape(null)).isEmpty();
    }

    @Test
    void escape_fieldWithComma_quoted() {
        assertThat(AuditLogCsvWriter.escape("a, b")).isEqualTo("\"a, b\"");
    }

    @Test
    void escape_fieldWithEmbeddedQuote_quotedAndDoubled() {
        assertThat(AuditLogCsvWriter.escape("say \"hi\"")).isEqualTo("\"say \"\"hi\"\"\"");
    }

    @Test
    void escape_formulaInjectionAttempt_prefixedWithApostrophe() {
        // actorEmail (self-service org signup) and detail (e.g. a target hostname echoed into a
        // TARGET_DELETED detail string) are both attacker-influenceable, same reasoning as
        // FindingCsvWriter's own escape - a leading =, +, -, @, tab, or CR would otherwise be
        // interpreted as a formula by Excel/Sheets when the exported file is opened.
        assertThat(AuditLogCsvWriter.escape("=cmd|'/c calc'!A1")).isEqualTo("'=cmd|'/c calc'!A1");
        assertThat(AuditLogCsvWriter.escape("+1+1")).startsWith("'+");
        assertThat(AuditLogCsvWriter.escape("@SUM(1,2)")).isEqualTo("\"'@SUM(1,2)\"");
    }

    @Test
    void escape_formulaCharacterMidString_notPrefixed() {
        assertThat(AuditLogCsvWriter.escape("total=5")).isEqualTo("total=5");
    }
}
