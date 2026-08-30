package org.freedonia.bloodhound.server.findings;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.freedonia.bloodhound.server.findings.dto.FindingSummary;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;

/**
 * Pure CSV formatting for a list of findings - see FindingController's /export endpoint. No
 * evidence/JSON blob column (see FindingRepository#findOpenForScoring's javadoc for why raw
 * evidence text is exactly the kind of payload bloat a bulk-findings response should leave out) -
 * just the fields a compliance/reporting audience actually wants in a spreadsheet.
 */
public final class FindingCsvWriter {

    private static final List<String> HEADER = List.of(
            "Display ID",
            "Severity",
            "Category",
            "Rule ID",
            "Title",
            "Description",
            "Affected Asset",
            "Status",
            "First Seen",
            "Last Seen",
            "Resolved At",
            "Remediation Advice");

    /** Same as {@link #HEADER}, plus a leading Target column - a row with no target context is meaningless once findings span more than one target. */
    private static final List<String> ORG_WIDE_HEADER = List.of(
            "Target",
            "Display ID",
            "Severity",
            "Category",
            "Rule ID",
            "Title",
            "Description",
            "Affected Asset",
            "Status",
            "First Seen",
            "Last Seen",
            "Resolved At",
            "Remediation Advice");

    private FindingCsvWriter() {}

    public static String write(List<FindingSummary> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", HEADER)).append("\r\n");
        for (FindingSummary f : findings) {
            sb.append(String.join(
                            ",",
                            escape(f.displayId()),
                            escape(f.severity()),
                            escape(f.category()),
                            escape(f.ruleId()),
                            escape(f.title()),
                            escape(f.description()),
                            escape(f.affectedAsset()),
                            escape(f.status()),
                            escape(formatInstant(f.firstSeenAt())),
                            escape(formatInstant(f.lastSeenAt())),
                            escape(formatInstant(f.resolvedAt())),
                            escape(f.remediationAdvice())))
                    .append("\r\n");
        }
        return sb.toString();
    }

    /**
     * The org-wide equivalent of {@link #write} - a product review found no way to export
     * findings across more than one target at a time existed anywhere, even after the org-wide
     * Findings page (which shares this exact filter model) shipped. Same escaping, same column
     * set, plus the target's hostname up front.
     */
    public static String writeOrgWide(List<OrgFindingSummary> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", ORG_WIDE_HEADER)).append("\r\n");
        for (OrgFindingSummary f : findings) {
            sb.append(String.join(
                            ",",
                            escape(f.targetHostname()),
                            escape(f.displayId()),
                            escape(f.severity()),
                            escape(f.category()),
                            escape(f.ruleId()),
                            escape(f.title()),
                            escape(f.description()),
                            escape(f.affectedAsset()),
                            escape(f.status()),
                            escape(formatInstant(f.firstSeenAt())),
                            escape(formatInstant(f.lastSeenAt())),
                            escape(formatInstant(f.resolvedAt())),
                            escape(f.remediationAdvice())))
                    .append("\r\n");
        }
        return sb.toString();
    }

    private static String formatInstant(Instant instant) {
        return instant == null ? "" : DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    /**
     * RFC 4180: a field containing a comma, quote, or newline is wrapped in quotes, with
     * embedded quotes doubled. Also guards against CSV/formula injection - a field starting
     * with =, +, -, @, tab, or CR gets interpreted as a formula by Excel/Sheets when the file
     * is opened, and finding text here is attacker-influenced (e.g. a ZAP alert title
     * reflecting a scanned page's own content, or a DNS-controlled hostname/TXT record), not a
     * hypothetical - the standard OWASP mitigation is a leading apostrophe to force text
     * interpretation.
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
