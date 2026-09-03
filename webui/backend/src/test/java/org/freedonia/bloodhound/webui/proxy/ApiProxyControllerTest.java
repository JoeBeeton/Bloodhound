package org.freedonia.bloodhound.webui.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

class ApiProxyControllerTest {

    private final RestClient centralServerClient = mock(RestClient.class);
    private final ApiProxyController controller = new ApiProxyController(centralServerClient);

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
}
