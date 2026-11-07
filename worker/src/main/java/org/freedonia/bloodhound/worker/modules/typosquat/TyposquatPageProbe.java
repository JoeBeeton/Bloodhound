package org.freedonia.bloodhound.worker.modules.typosquat;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;

/** One SSRF-guarded GET of a homepage: where it ends up, and whether it's a parking or bot-challenge page. */
public class TyposquatPageProbe {

    public record PageInfo(String landingHost, boolean parkingPage, boolean challengePage) {}

    private static final int MAX_REDIRECTS = 5;
    private static final int MAX_BODY_BYTES = 256_000;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    /** Domain marketplaces / parking landers a parked domain redirects to. */
    static final List<String> MARKETPLACE_HOST_SUFFIXES = List.of(
            "sedo.com", "dan.com", "afternic.com", "atom.com", "squadhelp.com", "hugedomains.com",
            "brandbucket.com", "namegarage.com", "undeveloped.com", "buydomains.com", "aftermarket.com",
            "namemagnet.com", "efty.com", "nameshift.com", "domainmarket.com", "uniregistry.com",
            "bodis.com", "parkingcrew.net", "above.com");

    private static final List<String> PARKING_MARKERS = List.of(
            "domain is for sale", "domain may be for sale", "this domain is for sale", "buy this domain",
            "make an offer on this domain", "inquire about this domain", "domain for sale",
            "this domain is parked", "parked free", "sedoparking", "parkingcrew",
            "window.location.href=\"/lander\"", "parklogic");

    /**
     * Client-side redirects only count on a page that's essentially just the redirect - a phishing
     * page commonly carries JS that forwards to the real brand after credentials are submitted.
     */
    private static final int MAX_REDIRECT_STUB_BYTES = 4_096;

    private static final List<String> CHALLENGE_MARKERS = List.of(
            "just a moment...", "attention required!", "quick security check", "verify you are human",
            "checking your browser", "_cf_chl", "cf-browser-verification", "challenge-platform",
            "px-captcha", "captcha-delivery.com", "/_incapsula_resource");

    private static final Pattern META_REFRESH = Pattern.compile(
            "<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"'][^\"']*url=([^\"'>\\s]+)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_REDIRECT = Pattern.compile(
            "(?:window\\.|document\\.|top\\.)?location(?:\\.href)?\\s*=\\s*[\"'](https?://[^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    /** Null when the host can't be fetched over HTTPS or HTTP - never throws. */
    public PageInfo probe(String hostname) {
        for (String scheme : List.of("https://", "http://")) {
            try {
                HttpResponse<InputStream> response = SafeHttpGet.get(
                        client,
                        scheme + hostname + "/",
                        REQUEST_TIMEOUT,
                        ScanUserAgent.VALUE,
                        HttpResponse.BodyHandlers.ofInputStream(),
                        MAX_REDIRECTS);
                String body = SafeHttpGet.readCappedUtf8(response.body(), MAX_BODY_BYTES);
                return classify(response.uri().getHost(), body);
            } catch (Exception e) {
                // try the next scheme
            }
        }
        return null;
    }

    static PageInfo classify(String responseHost, String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        String landingHost = clientSideRedirectHost(body);
        if (landingHost == null) {
            landingHost = responseHost == null ? null : responseHost.toLowerCase(Locale.ROOT);
        }
        boolean parking = PARKING_MARKERS.stream().anyMatch(lower::contains)
                || (landingHost != null && TyposquatDecisionLogic.hostUnderAny(landingHost, MARKETPLACE_HOST_SUFFIXES));
        boolean challenge = CHALLENGE_MARKERS.stream().anyMatch(lower::contains);
        return new PageInfo(landingHost, parking, challenge);
    }

    private static String clientSideRedirectHost(String body) {
        if (body.length() > MAX_REDIRECT_STUB_BYTES) {
            return null;
        }
        for (Pattern pattern : List.of(META_REFRESH, JS_REDIRECT)) {
            Matcher m = pattern.matcher(body);
            if (m.find()) {
                try {
                    String host = URI.create(m.group(1).trim()).getHost();
                    if (host != null) {
                        return host.toLowerCase(Locale.ROOT);
                    }
                } catch (IllegalArgumentException ignored) {
                    // not a usable absolute URL
                }
            }
        }
        return null;
    }
}
