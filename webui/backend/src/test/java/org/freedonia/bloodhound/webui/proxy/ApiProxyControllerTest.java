package org.freedonia.bloodhound.webui.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestBodySpec;
import org.springframework.web.client.RestClient.RequestBodyUriSpec;
import org.springframework.web.client.RestClient.ResponseSpec;

class ApiProxyControllerTest {

    private static final String BASE_URL = "http://central-server:8080";

    private final RestClient centralServerClient = mock(RestClient.class);
    private final ApiProxyController controller = new ApiProxyController(centralServerClient, BASE_URL);

    @Test
    void blockDirectAuthAccess_returnsNotFound() {
        // A security review found /api/v1/auth/** (login/refresh/etc.) fell into the broad
        // /api/v1/** wildcard the sibling proxy() method handles, so central-server's own raw-
        // token-returning auth endpoints were reachable through webui's own origin too -
        // alongside, not instead of, the intended cookie-based flow at /api/auth/**. This handler
        // is mapped ahead of that wildcard (Spring MVC prefers the more specific pattern for an
        // overlapping match, confirmed live) so a request under /api/v1/auth/** 404s here instead
        // of ever reaching the proxy method that would forward it to central-server.
        assertThat(controller.blockDirectAuthAccess().getStatusCode().value()).isEqualTo(404);
    }

    /**
     * Live incident: comparing 2+ targets on /compare (which joins their ids with a comma) 400'd
     * through this proxy while working fine hitting central-server directly. Root cause was
     * passing the raw, already-percent-encoded query string to RestClient's uri(String) overload,
     * which treats its argument as a URI TEMPLATE and re-encodes it - double-escaping the "%2C"
     * already in the raw query string into "%252C". Verifies the fix directly: the exact URI
     * handed to the RestClient must contain the query string byte-for-byte as received, with no
     * re-encoding of the already-encoded comma.
     */
    @Test
    void proxy_alreadyEncodedCommaInQueryString_forwardedWithoutDoubleEncoding() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/compare");
        when(request.getQueryString())
                .thenReturn("targetIds=11111111-1111-1111-1111-111111111111%2C22222222-2222-2222-2222-222222222222");

        RequestBodyUriSpec uriSpec = mock(RequestBodyUriSpec.class);
        RequestBodySpec bodySpec = mock(RequestBodySpec.class);
        ResponseSpec responseSpec = mock(ResponseSpec.class);
        when(centralServerClient.method(any())).thenReturn(uriSpec);
        when(uriSpec.uri(any(URI.class))).thenReturn(bodySpec);
        when(bodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.onStatus(any(), any())).thenReturn(responseSpec);
        when(responseSpec.toEntity(byte[].class))
                .thenReturn(ResponseEntity.status(HttpStatusCode.valueOf(200)).body(new byte[0]));

        controller.proxy(request, null);

        verify(uriSpec)
                .uri(URI.create(BASE_URL
                        + "/api/v1/compare?targetIds=11111111-1111-1111-1111-111111111111%2C22222222-2222-2222-2222-222222222222"));
    }
}
