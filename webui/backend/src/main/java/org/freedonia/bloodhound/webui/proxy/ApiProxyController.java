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
 * Transparent passthrough for /api/v1/** to central-server: forwards method,
 * path+query, body, and the browser's own Authorization header unchanged.
 * webui deliberately does not manage the access token itself here - unlike
 * /api/auth/** (see AuthProxyController), which owns the refresh-token
 * cookie, these are plain data calls the frontend already attaches its own
 * bearer token to. This keeps the browser on a single origin (no CORS needed
 * in dev or prod) without webui growing any real API logic of its own.
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
            value = "/api/v1/**",
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

        return spec.retrieve()
                .onStatus(HttpStatusCode::isError, (req, res) -> {})
                .toEntity(byte[].class);
    }

    @GetMapping({"/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**"})
    public ResponseEntity<byte[]> proxySwaggerDocs(HttpServletRequest request) {
        return proxy(request, null);
    }
}
