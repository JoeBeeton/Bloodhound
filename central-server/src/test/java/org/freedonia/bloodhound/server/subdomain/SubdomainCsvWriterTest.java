package org.freedonia.bloodhound.server.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.junit.jupiter.api.Test;

class SubdomainCsvWriterTest {

    private static SubdomainSummary summary(String hostname, boolean active, List<String> ips) {
        return new SubdomainSummary(
                UUID.randomUUID(), hostname, Instant.now(), Instant.now(), "CRTSH", active, ips, null, false);
    }

    @Test
    void write_headerRowFirst() {
        String csv = SubdomainCsvWriter.write(List.of());

        assertThat(csv).isEqualTo("Hostname,Status,Source,IP Addresses,First Seen,Last Seen\r\n");
    }

    @Test
    void write_activeSubdomain_statusColumnIsActive() {
        String csv = SubdomainCsvWriter.write(List.of(summary("a.example.com", true, List.of("1.2.3.4"))));

        assertThat(csv).contains("a.example.com,Active,CRTSH,1.2.3.4,");
    }

    @Test
    void write_inactiveSubdomain_statusColumnIsInactive() {
        String csv = SubdomainCsvWriter.write(List.of(summary("stale.example.com", false, List.of())));

        assertThat(csv).contains("stale.example.com,Inactive,CRTSH,,");
    }

    @Test
    void write_multipleIps_semicolonJoined() {
        // Semicolon-joined (not comma-joined) specifically so a multi-IP cell doesn't need CSV
        // quoting just to hold more than one address.
        String csv = SubdomainCsvWriter.write(List.of(summary("multi.example.com", true, List.of("1.1.1.1", "2.2.2.2"))));

        assertThat(csv).contains(",1.1.1.1; 2.2.2.2,");
    }

    @Test
    void escape_null_becomesEmptyString() {
        assertThat(SubdomainCsvWriter.escape(null)).isEmpty();
    }

    @Test
    void escape_fieldWithComma_quoted() {
        assertThat(SubdomainCsvWriter.escape("a, b")).isEqualTo("\"a, b\"");
    }

    @Test
    void escape_formulaInjectionAttempt_prefixedWithApostrophe() {
        // A subdomain hostname is discovered (CT logs, DNS), not user-typed - effectively
        // attacker-chosen text, same reasoning as FindingCsvWriter's own guard.
        assertThat(SubdomainCsvWriter.escape("=cmd|'/c calc'!A1")).isEqualTo("'=cmd|'/c calc'!A1");
    }
}
