package org.freedonia.bloodhound.worker.modules.whois;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RDAP first (structured JSON, reliable to parse), falling back to raw port-43
 * WHOIS only when RDAP isn't available for the TLD - free-text WHOIS format
 * is notoriously inconsistent across registries, so RDAP is preferred
 * wherever it exists.
 */
public class WhoisFetcher {

    private static final Logger log = LoggerFactory.getLogger(WhoisFetcher.class);
    private static final String BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
    private static final Duration TIMEOUT = Duration.ofSeconds(8);
    private static final int WHOIS_PORT = 43;
    private static final int SOCKET_TIMEOUT_MS = 8000;

    /**
     * A security review found both queryWhoisServer (raw port-43 sockets) and get (RDAP HTTP
     * fetches) read their entire response with no size limit at all - readAllBytes() and
     * BodyHandlers.ofString() respectively, the exact issue SafeHttpGet#readCappedUtf8 was
     * introduced to fix elsewhere (TechFetcher, DocumentFetcher, CrtShSource). The RDAP domain
     * lookup and the WHOIS referral-server query both hit a server this app doesn't control (the
     * queried hostname's own TLD registry) - a misbehaving or malicious one could stream gigabytes
     * within the request/socket timeout and exhaust the shared worker JVM's heap, same as the
     * already-fixed cases. Generous relative to TechFetcher/DocumentFetcher's 300,000-char page
     * caps since RDAP JSON (nested contact/entity objects) can legitimately run larger than one
     * HTML page's text, but WHOIS/RDAP domain records are never remotely close to megabytes for a
     * real domain either way.
     */
    private static final int MAX_RESPONSE_BYTES = 200_000;

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public WhoisFields fetch(String hostname) throws ScanModuleException {
        String tld = tldOf(hostname);
        WhoisFields viaRdap = tryRdap(hostname, tld);
        if (viaRdap != null) {
            return viaRdap;
        }
        log.info("RDAP unavailable for .{}, falling back to raw WHOIS for {}", tld, hostname);
        return tryRawWhoisFallback(hostname, tld);
    }

    private WhoisFields tryRdap(String hostname, String tld) {
        try {
            String bootstrapJson = get(BOOTSTRAP_URL);
            String rdapBase = RdapResponseParser.findRdapBaseUrl(bootstrapJson, tld);
            if (rdapBase == null) {
                return null;
            }
            String base = rdapBase.endsWith("/") ? rdapBase : rdapBase + "/";
            String domainJson = get(base + "domain/" + hostname);
            WhoisFields fields = RdapResponseParser.parseDomainResponse(domainJson);
            return fields.expiryDate() == null && fields.registrar() == null ? null : fields;
        } catch (Exception e) {
            return null;
        }
    }

    private WhoisFields tryRawWhoisFallback(String hostname, String tld) throws ScanModuleException {
        try {
            String ianaResponse = queryWhoisServer("whois.iana.org", tld);
            String referralServer = RawWhoisTextParser.parseReferralServer(ianaResponse);
            if (referralServer == null) {
                throw new ScanModuleException("no WHOIS referral server found for TLD ." + tld);
            }
            String domainResponse = queryWhoisServer(referralServer, hostname);
            return RawWhoisTextParser.parse(domainResponse);
        } catch (ScanModuleException e) {
            throw e;
        } catch (Exception e) {
            throw new ScanModuleException("WHOIS lookup failed for " + hostname, e);
        }
    }

    private String queryWhoisServer(String server, String query) throws IOException {
        // Every other raw-socket connect in this codebase re-validates the resolved address
        // immediately before connecting - this one didn't, a security review flagged as an
        // inconsistent outlier (low risk in practice: the two servers this is ever called with
        // are "whois.iana.org" and a referral server parsed from IANA's own authoritative
        // response, not attacker-influenced target data the way a scanned hostname/subdomain is
        // elsewhere - but worth the same guard for consistency and defense in depth).
        try (Socket socket = new Socket()) {
            InetAddress resolved = SafeAddressValidator.resolveSafeAddress(server);
            socket.connect(new InetSocketAddress(resolved, WHOIS_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            socket.getOutputStream().write((query + "\r\n").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            return SafeHttpGet.readCappedUtf8(socket.getInputStream(), MAX_RESPONSE_BYTES);
        }
    }

    private String get(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(TIMEOUT)
                .header("User-Agent", ScanUserAgent.VALUE)
                .GET()
                .build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            response.body().close();
            throw new IOException("HTTP " + response.statusCode() + " from " + url);
        }
        return SafeHttpGet.readCappedUtf8(response.body(), MAX_RESPONSE_BYTES);
    }

    static String tldOf(String hostname) {
        int lastDot = hostname.lastIndexOf('.');
        return lastDot < 0 ? hostname : hostname.substring(lastDot + 1);
    }
}
