package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.List;
import org.freedonia.bloodhound.worker.modules.common.FallbackDnsLookup;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * Fetch side of the passive hosting-provider lookup: the two-hop Team Cymru
 * IP-to-ASN DNS service (free, no API key, well-established passive
 * technique - see AsnDecisionLogic for the response format and the reasoning
 * for it). Uses the shared public-then-system resolver path ({@link
 * FallbackDnsLookup}) over UDP since Cymru's TXT responses are tiny (same
 * reasoning as SubdomainDnsResolver's A/AAAA/CNAME lookups, unlike
 * DnsRecordFetcher's large apex TXT sets which need TCP).
 */
public class AsnFetcher {

    private final FallbackDnsLookup dns = new FallbackDnsLookup(false);

    /** Returns {asn, asnOrg} (either or both null if the IP is neither plain IPv4 nor IPv6, or a lookup step comes back empty). */
    public AsnLookupResult lookup(String ip) {
        String reversed = AsnDecisionLogic.reverseIpv4(ip);
        String originZone = "origin.asn.cymru.com";
        if (reversed == null) {
            reversed = AsnDecisionLogic.reverseIpv6(ip);
            originZone = "origin6.asn.cymru.com";
        }
        if (reversed == null) {
            return new AsnLookupResult(null, null);
        }
        String originTxt = firstTxt(reversed + "." + originZone);
        String asn = AsnDecisionLogic.parseAsn(originTxt);
        if (asn == null) {
            return new AsnLookupResult(null, null);
        }
        // Same AS-name zone for both families - it's keyed by ASN, not by IP.
        String asnTxt = firstTxt(asn + ".asn.cymru.com");
        String org = AsnDecisionLogic.parseOrg(asnTxt);
        return new AsnLookupResult(asn, org);
    }

    private String firstTxt(String name) {
        List<String> values = queryTxt(name);
        return values.isEmpty() ? null : values.get(0);
    }

    private List<String> queryTxt(String name) {
        return dns.lookup(name, Type.TXT).records().stream()
                .filter(TXTRecord.class::isInstance)
                .map(r -> String.join("", ((TXTRecord) r).getStrings()))
                .toList();
    }
}
