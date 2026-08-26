package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Pure parsing/mapping logic for the Team Cymru IP-to-ASN DNS lookup - no
 * network calls, fully unit-testable against canned TXT-record strings. See
 * AsnFetcher for the two DNS hops this supports:
 *
 * <ol>
 *   <li>origin lookup ({@code {reversed-ip}.origin.asn.cymru.com} TXT, or
 *       {@code {reversed-ip}.origin6.asn.cymru.com} for IPv6 - see {@link
 *       #reverseIpv6}) returns e.g. {@code "15169 | 8.8.8.0/24 | US | arin |
 *       2000-03-30"} - field 0 is the ASN.</li>
 *   <li>AS-name lookup ({@code AS{asn}.asn.cymru.com} TXT - same zone for
 *       both families, since it's keyed by ASN, not IP) returns e.g.
 *       {@code "15169 | US | arin | 2000-03-30 | GOOGLE, US"} - the last field is the org name.</li>
 * </ol>
 */
public final class AsnDecisionLogic {

    private AsnDecisionLogic() {}

    /**
     * Reverses an IPv4 dotted-quad for the Cymru origin-lookup query name
     * (same octet-reversal convention as in-addr.arpa PTR lookups). Returns
     * null for anything that isn't a plain IPv4 address.
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

    /**
     * Reverses an IPv6 literal into Cymru's nibble-reversed query-name format
     * for {@code origin6.asn.cymru.com} - the same convention ip6.arpa PTR
     * lookups use (every hex nibble of the full 128-bit address, reversed,
     * dot-separated), but against a different zone than the IPv4 origin
     * lookup. Returns null for anything that isn't a plain IPv6 address -
     * deliberately checks for a literal ':' first so this never risks
     * triggering a real DNS lookup via {@link InetAddress#getByName} on a
     * hostname (that method only resolves locally for a literal IP address;
     * for anything else it would perform actual network I/O, which pure
     * decision logic must never do). An IPv4-mapped IPv6 literal (e.g.
     * {@code ::ffff:10.0.0.1}) is normalized by the JDK to an
     * {@code Inet4Address} before it gets here, so it correctly falls
     * through to null rather than being nibble-reversed as if it were a
     * genuine IPv6 address.
     */
    public static String reverseIpv6(String ip) {
        if (ip == null || !ip.contains(":")) {
            return null;
        }
        InetAddress address;
        try {
            address = InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
        if (!(address instanceof Inet6Address)) {
            return null;
        }
        byte[] bytes = address.getAddress();
        StringBuilder nibbles = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            nibbles.append(String.format("%02x", b));
        }
        StringBuilder reversed = new StringBuilder(nibbles.length() * 2 - 1);
        for (int i = nibbles.length() - 1; i >= 0; i--) {
            reversed.append(nibbles.charAt(i));
            if (i > 0) {
                reversed.append('.');
            }
        }
        return reversed.toString();
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
