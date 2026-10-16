package org.freedonia.bloodhound.worker.modules.http;

import java.util.List;
import java.util.Map;

/**
 * Raw fetch output for one hostname - headers keyed lowercase, first value each; raw Set-Cookie
 * lines kept intact for the parser. {@code plainHttp} is what a single {@code http://host/} GET
 * returned with no redirects followed (status + raw Location), or null when port 80 didn't
 * answer at all - the input to HTTP_NO_HTTPS_REDIRECT. {@code cors} is the response to a GET
 * carrying a fabricated {@code Origin} header, or null if that probe itself failed - the input
 * to CORS_CREDENTIALED_ORIGIN_REFLECTION.
 */
public record FetchResult(
        boolean https,
        Map<String, String> headers,
        List<String> setCookieHeaders,
        PlainHttpProbe plainHttp,
        CorsProbe cors,
        TraceProbe trace) {

    public FetchResult(
            boolean https, Map<String, String> headers, List<String> setCookieHeaders, PlainHttpProbe plainHttp,
            CorsProbe cors) {
        this(https, headers, setCookieHeaders, plainHttp, cors, null);
    }

    public FetchResult(boolean https, Map<String, String> headers, List<String> setCookieHeaders) {
        this(https, headers, setCookieHeaders, null, null, null);
    }

    public record PlainHttpProbe(int status, String location) {}

    /** Raw Access-Control-Allow-* response headers to the fabricated-Origin probe - either may be null if absent. */
    public record CorsProbe(String allowOrigin, String allowCredentials) {}

    /** The response to a TRACE request - null if the probe itself failed (connection refused, etc., treated as "couldn't check", not a finding). statusCode 200 means the server actually processed TRACE rather than rejecting it (405/501/other); echoedMarker confirms the response body contains this probe's own distinctive marker, the stronger (but not required) signal of genuine RFC 7231 TRACE loop-back behavior. */
    public record TraceProbe(int statusCode, boolean echoedMarker) {}
}
