package org.freedonia.bloodhound.worker.modules.http;

import java.util.List;
import java.util.Map;

/**
 * Raw fetch output for one hostname - headers keyed lowercase, first value each; raw Set-Cookie
 * lines kept intact for the parser. {@code plainHttp} is what a single {@code http://host/} GET
 * returned with no redirects followed (status + raw Location), or null when port 80 didn't
 * answer at all - the input to HTTP_NO_HTTPS_REDIRECT.
 */
public record FetchResult(
        boolean https, Map<String, String> headers, List<String> setCookieHeaders, PlainHttpProbe plainHttp) {

    public FetchResult(boolean https, Map<String, String> headers, List<String> setCookieHeaders) {
        this(https, headers, setCookieHeaders, null);
    }

    public record PlainHttpProbe(int status, String location) {}
}
