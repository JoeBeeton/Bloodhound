package org.freedonia.bloodhound.server.audit;

import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Pure CSV formatting for a list of audit log entries - see AuditLogController's /export
 * endpoint. Same column set the admin page's table already shows (When/Actor/Action/Detail),
 * plus Target Type/Target ID for a reader who needs to correlate an entry back to the specific
 * record it acted on, which the table itself omits for space.
 */
public final class AuditLogCsvWriter {

    private static final List<String> HEADER =
            List.of("When", "Actor", "Action", "Target Type", "Target ID", "Detail");

    private AuditLogCsvWriter() {}

    public static String write(List<AuditLogEntry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", HEADER)).append("\r\n");
        for (AuditLogEntry e : entries) {
            sb.append(String.join(
                            ",",
                            escape(DateTimeFormatter.ISO_INSTANT.format(e.createdAt())),
                            escape(e.actorEmail()),
                            escape(e.action()),
                            escape(e.targetType()),
                            escape(e.targetId()),
                            escape(e.detail())))
                    .append("\r\n");
        }
        return sb.toString();
    }

    /**
     * Same RFC 4180 + CSV/formula-injection guard as FindingCsvWriter#escape - actor_email and
     * detail are both attacker-influenceable (a self-service org signup email, a target hostname
     * echoed into a TARGET_DELETED detail string), so the same leading-apostrophe mitigation
     * against a field starting with =, +, -, @, tab, or CR applies here too.
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
