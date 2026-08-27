package org.freedonia.bloodhound.webui.proxy;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Transparent passthrough for /api/v1/** and /scim/v2/** to central-server:
 * forwards method, path+query, body, and the browser's/client's own
 * Authorization header unchanged. webui deliberately does not manage the
 * access token itself here - unlike /api/auth/** (see AuthProxyController),
 * which owns the refresh-token cookie, these are plain data calls the caller
 * already attaches its own bearer token to. This keeps the browser on a
 * single origin (no CORS needed in dev or prod) without webui growing any
 * real API logic of its own.
 *
 * <p>/scim/v2/** was missing here entirely until a live API review caught
 * it: with no route registered for it, a GET fell through to
 * SpaFallbackController's catch-all (any extension-less, non-api/assets
 * path forwards to index.html), which registers that literal path for GET -
 * so a non-GET SCIM request (an IdP's POST to provision a user, say) got a
 * locally-synthesized 405 "Method Not Allowed" from Spring MVC itself,
 * never reaching central-server's real SCIM implementation at all.
 *
 * <p>Also forwards the read-only API's own documentation (/swagger-ui.html
 * and friends) for the same single-origin reason - central-server's
 * springdoc setup already permits these paths unauthenticated (see its
 * SecurityConfig), but they live outside /api/v1/**, so the ApiKeysPage
 * link to /swagger-ui.html 404'd against webui's own origin until this was
 * added: confirmed live, curl against http://localhost:8090/swagger-ui.html
 * returned Spring Boot's default 404 (no static resource by that name) since
 * SpaFallbackController's catch-all only forwards extension-less paths to
 * index.html, and this literal path was never routed anywhere else.
 */
@RestController
public class ApiProxyController {

    private final RestClient centralServerClient;

    public ApiProxyController(RestClient centralServerClient) {
        this.centralServerClient = centralServerClient;
    }

    @RequestMapping(
            value = {"/api/v1/**", "/scim/v2/**"},
            method = {
                RequestMethod.GET,
                RequestMethod.POST,
                RequestMethod.PATCH,
                RequestMethod.PUT,
                RequestMethod.DELETE
            })
    public ResponseEntity<byte[]> proxy(HttpServletRequest request, @RequestBody(required = false) byte[] body) {
        String query = request.getQueryString();
        String uri = request.getRequestURI() + (query != null ? "?" + query : "");

        RestClient.RequestBodySpec spec =
                centralServerClient.method(HttpMethod.valueOf(request.getMethod())).uri(uri);
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        if (body != null && body.length > 0) {
            spec = spec.contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ResponseEntity<byte[]> upstream =
                spec.retrieve().onStatus(HttpStatusCode::isError, (req, res) -> {}).toEntity(byte[].class);

        // Hop-by-hop headers describe the framing of the specific TCP connection between this
        // proxy and central-server - they must not be copied onto the separate connection
        // between the browser/client and webui, whose framing Tomcat computes fresh for
        // whatever byte[] body is actually being written here. Found live: forwarding
        // Transfer-Encoding verbatim left TWO "Transfer-Encoding: chunked" header lines in
        // webui's own response (the copied-through one plus Tomcat's own, real one), which is
        // exactly the kind of duplicate/conflicting framing header HTTP/1.1 forbids (RFC 7230
        // 3.3.1) - confirmed live that curl's chunked decoder chokes on it ("chunk hex-length
        // char not a hex digit"), landing on the response body's own leading '{' as if it were
        // chunk-size text.
        HttpHeaders headers = new HttpHeaders();
        headers.addAll(upstream.getHeaders());
        headers.remove(HttpHeaders.TRANSFER_ENCODING);
        headers.remove(HttpHeaders.CONTENT_LENGTH);
        headers.remove(HttpHeaders.CONNECTION);

        return ResponseEntity.status(upstream.getStatusCode()).headers(headers).body(upstream.getBody());
    }

    @GetMapping({"/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**"})
    public ResponseEntity<byte[]> proxySwaggerDocs(HttpServletRequest request) {
        return proxy(request, null);
    }
}
