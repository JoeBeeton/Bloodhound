package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.net.UnknownHostException;
import java.util.List;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Fetch side of the passive hosting-provider lookup: the two-hop Team Cymru
 * IP-to-ASN DNS service (free, no API key, well-established passive
 * technique - see AsnDecisionLogic for the response format and the reasoning
 * for it). Uses the same public resolver (Cloudflare 1.1.1.1) as every other
 * DNS-based module in this project, over UDP since Cymru's TXT responses are
 * tiny (same reasoning as SubdomainDnsResolver's A/AAAA/CNAME lookups, unlike
 * DnsRecordFetcher's large apex TXT sets which needed TCP).
 */
public class AsnFetcher {

    private static final String PUBLIC_RESOLVER = "1.1.1.1";

    private final Resolver resolver;

    public AsnFetcher() {
        try {
            this.resolver = new SimpleResolver(PUBLIC_RESOLVER);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
    }

    /** Returns {asn, asnOrg} (either or both null if the IP isn't plain IPv4 or a lookup step comes back empty). */
    public AsnLookupResult lookup(String ip) {
        String reversed = AsnDecisionLogic.reverseIpv4(ip);
        if (reversed == null) {
            return new AsnLookupResult(null, null);
        }
        String originTxt = firstTxt(reversed + ".origin.asn.cymru.com");
        String asn = AsnDecisionLogic.parseAsn(originTxt);
        if (asn == null) {
            return new AsnLookupResult(null, null);
        }
        String asnTxt = firstTxt(asn + ".asn.cymru.com");
        String org = AsnDecisionLogic.parseOrg(asnTxt);
        return new AsnLookupResult(asn, org);
    }

    private String firstTxt(String name) {
        List<String> values = queryTxt(name);
        return values.isEmpty() ? null : values.get(0);
    }

    private List<String> queryTxt(String name) {
        try {
            Lookup lookup = new Lookup(name, Type.TXT);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (records == null) {
                return List.of();
            }
            return java.util.Arrays.stream(records)
                    .filter(TXTRecord.class::isInstance)
                    .map(r -> String.join("", ((TXTRecord) r).getStrings()))
                    .toList();
        } catch (TextParseException | IllegalArgumentException e) {
            return List.of();
        }
    }
}
