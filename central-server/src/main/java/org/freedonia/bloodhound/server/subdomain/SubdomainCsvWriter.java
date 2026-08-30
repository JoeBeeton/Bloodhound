package org.freedonia.bloodhound.server.subdomain;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;

/**
 * Pure CSV formatting for a target's discovered subdomains - see SubdomainController's /export
 * endpoint. Findings and the audit log already had a CSV export (FindingCsvWriter,
 * AuditLogCsvWriter); a product review found the subdomains list - the actual asset inventory an
 * ASM tool exists to produce - had no export at all, despite being exactly the kind of list a
 * user needs to hand off to another tool (an internal CMDB, a vuln scanner's target list) or a
 * report.
 */
public final class SubdomainCsvWriter {

    private static final List<String> HEADER =
            List.of("Hostname", "Status", "Source", "IP Addresses", "First Seen", "Last Seen");

    private SubdomainCsvWriter() {}

    public static String write(List<SubdomainSummary> subdomains) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", HEADER)).append("\r\n");
        for (SubdomainSummary s : subdomains) {
            sb.append(String.join(
                            ",",
                            escape(s.hostname()),
                            s.isActive() ? "Active" : "Inactive",
                            escape(s.source()),
                            escape(String.join("; ", s.currentIpAddresses())),
                            escape(formatInstant(s.firstSeenAt())),
                            escape(formatInstant(s.lastSeenAt()))))
                    .append("\r\n");
        }
        return sb.toString();
    }

    private static String formatInstant(Instant instant) {
        return instant == null ? "" : DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    /**
     * Same RFC 4180 + formula-injection guard as FindingCsvWriter#escape - hostname and source
     * are both attacker-influenceable here (a subdomain discovered via CT logs or DNS is
     * effectively attacker-chosen text, e.g. a hostile "=cmd|...".evil.com), so the same leading
     * apostrophe mitigation applies even though a hostname isn't free text like a finding title.
     */
    static String escape(String value) {
        if (value == null) {
            return "";
        }
        String v = value;
        char first = v.isEmpty() ? '\0' : v.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r') {
            v = "'" + v;
        }
        if (v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r")) {
            return "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }
}
