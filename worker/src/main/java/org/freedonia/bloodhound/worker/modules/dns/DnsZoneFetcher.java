package org.freedonia.bloodhound.worker.modules.dns;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.ZoneTransferException;
import org.xbill.DNS.ZoneTransferIn;

/**
 * Fetch side of the zone-level checks (AXFR + lame delegation) - see
 * DnsZoneDecisionLogic for interpretation. Split from DnsRecordFetcher
 * because these are per-nameserver active queries (resolve each NS, then
 * connect to it directly) rather than simple name/type lookups against the
 * one public resolver.
 */
public class DnsZoneFetcher {

    private static final String PUBLIC_RESOLVER = "1.1.1.1";
    private static final Duration TIMEOUT = Duration.ofSeconds(6);

    private final Resolver publicResolver;

    public DnsZoneFetcher() {
        try {
            this.publicResolver = new SimpleResolver(PUBLIC_RESOLVER);
        } catch (java.net.UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
    }

    public record NsCheckResult(String nameserver, boolean axfrAllowed, int axfrRecordCount, boolean answeredAuthoritatively) {}

    public List<NsCheckResult> fetch(String hostname) {
        List<String> nsHostnames = queryNsHostnames(hostname);
        List<NsCheckResult> results = new ArrayList<>();
        for (String ns : nsHostnames) {
            String nsIp = resolveA(ns);
            if (nsIp == null) {
                // Can't reach this NS at all from here - not evidence of anything, just skip it
                // rather than guessing at either a positive or negative finding.
                continue;
            }
            boolean answersAuthoritatively = respondsAuthoritatively(hostname, nsIp);
            AxfrAttempt axfr = attemptAxfr(hostname, nsIp);
            results.add(new NsCheckResult(ns, axfr.allowed(), axfr.recordCount(), answersAuthoritatively));
        }
        return results;
    }

    private List<String> queryNsHostnames(String hostname) {
        List<String> hostnames = new ArrayList<>();
        try {
            Lookup lookup = new Lookup(hostname, Type.NS);
            lookup.setResolver(publicResolver);
            Record[] records = lookup.run();
            if (records != null) {
                for (Record record : records) {
                    if (record instanceof NSRecord ns) {
                        hostnames.add(ns.getTarget().toString(true));
                    }
                }
            }
        } catch (Exception ignored) {
            // no NS records resolvable - empty list, no findings from this check
        }
        return hostnames;
    }

    private String resolveA(String hostname) {
        try {
            Lookup lookup = new Lookup(hostname, Type.A);
            lookup.setResolver(publicResolver);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                return null;
            }
            return ((ARecord) records[0]).getAddress().getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Queries the zone's SOA directly against a specific nameserver's IP
     * (bypassing the public resolver entirely) and treats a real SOA answer
     * for the exact zone as "authoritative". A timeout, refusal, or empty
     * answer is treated as lame - but see DnsZoneDecisionLogic for how this
     * is scored: a single unreachable NS from our vantage point is weaker
     * evidence than the AXFR check's unambiguous "it transferred the zone"
     * signal, so this stays Medium, not Critical.
     */
    private boolean respondsAuthoritatively(String hostname, String nsIp) {
        try {
            SimpleResolver directResolver = new SimpleResolver(nsIp);
            directResolver.setTimeout(TIMEOUT);
            Lookup lookup = new Lookup(hostname, Type.SOA);
            lookup.setResolver(directResolver);
            Record[] records = lookup.run();
            return records != null && records.length > 0 && records[0] instanceof SOARecord;
        } catch (Exception e) {
            return false;
        }
    }

    private record AxfrAttempt(boolean allowed, int recordCount) {}

    /**
     * A security review found this had no cap on record count/bytes at all - dnsjava's default
     * (handler-less) {@code run()} buffers every transferred record into one in-memory list with
     * no limit, and the only real bound was a 6-second idle timeout, which a nameserver streaming
     * fast enough (a misconfigured server on a large zone, reachable via a target's own
     * attacker-influenceable NS delegation - this is by definition an external, untrusted server)
     * could avoid ever hitting while still exhausting the shared worker JVM's heap. Caps the
     * transfer itself via a {@link ZoneTransferIn.ZoneTransferHandler}, not just a post-hoc
     * truncation of an already-fully-buffered list, the same "stop the read itself, don't just
     * discard after" reasoning {@link org.freedonia.bloodhound.common.net.SafeHttpGet#readCappedUtf8}
     * already applies to HTTP bodies.
     */
    static final int MAX_AXFR_RECORDS = 50_000;

    /**
     * Unchecked so it can propagate straight out of {@link ZoneTransferIn.ZoneTransferHandler#handleRecord}
     * (which only declares the checked {@link ZoneTransferException}) past dnsjava's internal
     * transfer loop to {@link #attemptAxfr}'s own catch below, without dnsjava mistaking it for a
     * normal protocol-level abort. Deliberately distinct from every other failure path: hitting
     * the cap means AXFR genuinely succeeded (records were flowing) right up until this code chose
     * to stop it - that must still report {@code allowed=true}. Silently falling into the same
     * catch-all as a real refusal would turn a positive "yes, this nameserver allows zone
     * transfers" finding into a false negative purely because the zone happened to be large -
     * exactly backwards for a security check.
     */
    static final class AxfrRecordCapExceeded extends RuntimeException {}

    static final class CappedAxfrHandler implements ZoneTransferIn.ZoneTransferHandler {
        final List<Record> records = new ArrayList<>();

        @Override
        public void startAXFR() {}

        @Override
        public void startIXFR() {}

        @Override
        public void startIXFRDeletes(Record soa) {}

        @Override
        public void startIXFRAdds(Record soa) {}

        @Override
        public void handleRecord(Record record) {
            if (records.size() >= MAX_AXFR_RECORDS) {
                throw new AxfrRecordCapExceeded();
            }
            records.add(record);
        }
    }

    private AxfrAttempt attemptAxfr(String hostname, String nsIp) {
        CappedAxfrHandler handler = new CappedAxfrHandler();
        try {
            ZoneTransferIn xfr = ZoneTransferIn.newAXFR(Name.fromString(hostname, Name.root), nsIp, null);
            // Duration overload, not the int-seconds one (deprecated in dnsjava 3.6.1) - found
            // while already touching this method for the AXFR record cap below.
            xfr.setTimeout(TIMEOUT);
            xfr.run(handler);
            // A well-behaved refusal throws (ZoneTransferException) rather than returning here, but
            // guard against an empty-but-successful transfer being misread as a positive too.
            return new AxfrAttempt(!handler.records.isEmpty(), handler.records.size());
        } catch (AxfrRecordCapExceeded e) {
            // See the class's own javadoc: capped mid-transfer is still a real "yes" finding, not
            // a refusal - the nameserver was actively streaming zone data when we chose to stop.
            return new AxfrAttempt(true, handler.records.size());
        } catch (Exception e) {
            // The expected, correct outcome for a properly-configured nameserver: refused/reset/timeout.
            return new AxfrAttempt(false, 0);
        }
    }
}
