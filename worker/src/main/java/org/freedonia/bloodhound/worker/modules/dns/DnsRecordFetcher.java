package org.freedonia.bloodhound.worker.modules.dns;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Fetch side of the DNS posture check: raw record queries only, no
 * interpretation - see DnsPostureParser for that. Uses dnsjava rather than
 * raw JNDI DNS contexts (simpler API, no native deps).
 *
 * <p>Queries go directly to a public recursive resolver (Cloudflare's
 * 1.1.1.1) over TCP, rather than whatever DNS is configured in the
 * container/host. Discovered against a real target (github.com): its apex
 * TXT set is large enough (SPF plus several site-verification records) that
 * a plain UDP query through Docker's embedded DNS resolver (127.0.0.11) came
 * back SERVFAIL rather than transparently retrying over TCP itself, and a
 * DNSKEY query through the same embedded resolver came back NOTIMP - a
 * simple forwarding proxy, not a full recursive resolver. A scanning tool
 * needs complete, correct answers for every record type regardless of the
 * deployment environment's local stub resolver, so querying a known-good
 * public resolver directly is the reliable choice; TCP has no response-size
 * limit, at the cost of a few extra milliseconds per lookup.
 */
public class DnsRecordFetcher {

    private static final String PUBLIC_RESOLVER = "1.1.1.1";

    /**
     * Common DKIM selector names, per every ASM/security-scanner's shared
     * caveat: the real selector is chosen by whoever configured the mail
     * system and isn't discoverable generically, so this is inherently a
     * best-effort probe of the handful of names actually seen in practice
     * (Google Workspace's "google", Mailchimp/generic "k1", and the plain
     * "default"/"selector1"/"selector2" convention several ESPs default to).
     */
    private static final List<String> COMMON_DKIM_SELECTORS =
            List.of("default", "google", "selector1", "selector2", "k1", "dkim");

    private final Resolver resolver;
    private final HttpClient httpClient;

    public DnsRecordFetcher() {
        try {
            SimpleResolver simpleResolver = new SimpleResolver(PUBLIC_RESOLVER);
            simpleResolver.setTCP(true);
            this.resolver = simpleResolver;
        } catch (java.net.UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
        this.httpClient =
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    public DnsRecords fetch(String hostname) {
        List<String> txt = queryTxt(hostname);
        List<String> dmarcTxt = queryTxt("_dmarc." + hostname);
        boolean caaPresent = !queryRecords(hostname, Type.CAA).isEmpty();
        boolean dnskeyPresent = !queryRecords(hostname, Type.DNSKEY).isEmpty();

        boolean mtaStsTxt = queryTxt("_mta-sts." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=stsv1"));
        boolean mtaStsPolicy = fetchesOk("https://mta-sts." + hostname + "/.well-known/mta-sts.txt");
        boolean tlsRpt = queryTxt("_smtp._tls." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=tlsrptv1"));
        boolean bimi = queryTxt("default._bimi." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=bimi1"));

        List<String> dkimSelectorsFound = new ArrayList<>();
        for (String selector : COMMON_DKIM_SELECTORS) {
            if (!queryTxt(selector + "._domainkey." + hostname).isEmpty()) {
                dkimSelectorsFound.add(selector);
            }
        }

        boolean wildcard = probeWildcard(hostname);

        return new DnsRecords(
                txt, dmarcTxt, caaPresent, dnskeyPresent, mtaStsTxt, mtaStsPolicy, tlsRpt, bimi, dkimSelectorsFound, wildcard);
    }

    /** A definitely-nonexistent name resolving at all means the zone has wildcard DNS configured on its apex. */
    private boolean probeWildcard(String hostname) {
        String probe = "bh-wildcard-probe-" + UUID.randomUUID().toString().replace("-", "") + "." + hostname;
        return !queryRecords(probe, Type.A).isEmpty();
    }

    private boolean fetchesOk(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Bloodhound-ASM/1.0 (+passive surface scan)")
                    .GET()
                    .build();
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> queryTxt(String name) {
        List<String> values = new ArrayList<>();
        for (Record record : queryRecords(name, Type.TXT)) {
            if (record instanceof TXTRecord txt) {
                values.add(String.join("", txt.getStrings()));
            }
        }
        return values;
    }

    private List<Record> queryRecords(String name, int type) {
        try {
            Lookup lookup = new Lookup(name, type);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            return records == null ? List.of() : List.of(records);
        } catch (TextParseException | IllegalArgumentException e) {
            // Malformed name (e.g. "_dmarc." + an already-invalid hostname)
            // or no resolver available - treat as "no records", not a hard failure.
            return List.of();
        }
    }
}
