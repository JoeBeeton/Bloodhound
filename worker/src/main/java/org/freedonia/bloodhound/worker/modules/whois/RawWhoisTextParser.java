package org.freedonia.bloodhound.worker.modules.whois;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Best-effort parsing of free-text WHOIS server responses (port 43) - used
 * only when RDAP isn't available for a TLD. Free-text WHOIS format varies
 * across registries; this covers the common field labels used by
 * ICANN-2013-RAA-compliant gTLD registrars, which is the large majority of
 * real-world lookups. Pure text parsing, no network calls, unit-testable
 * against canned response fixtures.
 */
public final class RawWhoisTextParser {

    private static final Pattern REGISTRAR = Pattern.compile("(?im)^Registrar:\\s*(.+)$");
    private static final Pattern EXPIRY = Pattern.compile(
            "(?im)^(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|paid-till):\\s*(.+)$");
    private static final Pattern CREATED =
            Pattern.compile("(?im)^(?:Creation Date|Registered On|Domain Registration Date):\\s*(.+)$");
    private static final Pattern NAME_SERVER = Pattern.compile("(?im)^Name Server:\\s*(.+)$");
    private static final Pattern REFER = Pattern.compile("(?im)^refer:\\s*(\\S+)");
    // ICANN-2013-RAA's standard "Domain Status:" line is "<code> <url>" - only the code (the
    // first token) is captured, same as RDAP's own bare status-keyword array, so both fetch
    // paths feed WhoisDecisionLogic identically-shaped data.
    private static final Pattern DOMAIN_STATUS = Pattern.compile("(?im)^Domain Status:\\s*(\\S+)");

    private RawWhoisTextParser() {}

    public static WhoisFields parse(String text) {
        if (text == null || text.isBlank()) {
            return WhoisFields.empty(true);
        }
        String registrar = firstGroup(REGISTRAR, text);
        Instant created = parseDate(firstGroup(CREATED, text));
        Instant expiry = parseDate(firstGroup(EXPIRY, text));
        List<String> nameServers = new ArrayList<>();
        Matcher nsMatcher = NAME_SERVER.matcher(text);
        while (nsMatcher.find()) {
            nameServers.add(nsMatcher.group(1).trim().toLowerCase(java.util.Locale.ROOT));
        }
        List<String> statusCodes = new ArrayList<>();
        Matcher statusMatcher = DOMAIN_STATUS.matcher(text);
        while (statusMatcher.find()) {
            statusCodes.add(statusMatcher.group(1).trim());
        }
        return new WhoisFields(
                registrar, created, expiry, null, nameServers, Map.of("rawText", text), true, statusCodes);
    }

    /** Extracts the referral WHOIS server hostname from an IANA "whois.iana.org" TLD response. */
    public static String parseReferralServer(String ianaResponse) {
        return firstGroup(REFER, ianaResponse);
    }

    private static String firstGroup(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).trim() : null;
    }

    /** WHOIS date formats vary (ISO-8601 with/without fractional seconds being the most common); best-effort, returns null rather than throwing on an unrecognized shape. */
    private static Instant parseDate(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            try {
                return java.time.LocalDate.parse(value, DateTimeFormatter.ISO_LOCAL_DATE)
                        .atStartOfDay(java.time.ZoneOffset.UTC)
                        .toInstant();
            } catch (Exception e2) {
                return null;
            }
        }
    }
}
