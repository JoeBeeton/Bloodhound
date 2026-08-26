package org.freedonia.bloodhound.worker.modules.fingerprint;

/**
 * Pure parsing/mapping logic for the Team Cymru IP-to-ASN DNS lookup - no
 * network calls, fully unit-testable against canned TXT-record strings. See
 * AsnFetcher for the two DNS hops this supports:
 *
 * <ol>
 *   <li>origin lookup ({@code {reversed-ip}.origin.asn.cymru.com} TXT) returns
 *       e.g. {@code "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"} - field 0 is the ASN.</li>
 *   <li>AS-name lookup ({@code AS{asn}.asn.cymru.com} TXT) returns e.g.
 *       {@code "15169 | US | arin | 2000-03-30 | GOOGLE, US"} - the last field is the org name.</li>
 * </ol>
 */
public final class AsnDecisionLogic {

    private AsnDecisionLogic() {}

    /**
     * Reverses an IPv4 dotted-quad for the Cymru origin-lookup query name
     * (same octet-reversal convention as in-addr.arpa PTR lookups). Returns
     * null for anything that isn't a plain IPv4 address - IPv6 support would
     * need Cymru's nibble-reversed ip6.arpa-style query format, meaningfully
     * more involved, and is deliberately out of scope here; an IPv6-only
     * host simply gets no hosting-provider data rather than a wrong one.
     */
    public static String reverseIpv4(String ip) {
        if (ip == null) {
            return null;
        }
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            return null;
        }
        for (String octet : octets) {
            try {
                int value = Integer.parseInt(octet);
                if (value < 0 || value > 255) {
                    return null;
                }
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0];
    }

    /** Parses the origin-lookup TXT record into "AS{number}", or null if malformed/empty. */
    public static String parseAsn(String originTxtRecord) {
        if (originTxtRecord == null || originTxtRecord.isBlank()) {
            return null;
        }
        String[] parts = originTxtRecord.split("\\|");
        if (parts.length == 0) {
            return null;
        }
        String number = parts[0].trim();
        return number.isEmpty() ? null : "AS" + number;
    }

    /** Parses the AS-name-lookup TXT record into its organization field (the last pipe-delimited value), or null if malformed/empty. */
    public static String parseOrg(String asnTxtRecord) {
        if (asnTxtRecord == null || asnTxtRecord.isBlank()) {
            return null;
        }
        String[] parts = asnTxtRecord.split("\\|");
        if (parts.length == 0) {
            return null;
        }
        String org = parts[parts.length - 1].trim();
        return org.isEmpty() ? null : org;
    }
}
