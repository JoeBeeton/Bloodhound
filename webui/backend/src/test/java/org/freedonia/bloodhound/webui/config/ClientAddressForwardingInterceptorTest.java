package org.freedonia.bloodhound.webui.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ClientAddressForwardingInterceptorTest {

    private static MockHttpServletRequest from(String peer, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }

    @Test
    void behindTheInternalProxy_usesTheAddressTheProxyAppended() {
        assertThat(ClientAddressForwardingInterceptor.clientAddress(from("172.20.0.3", "203.0.113.50")))
                .isEqualTo("203.0.113.50");
    }

    @Test
    void behindTheInternalProxy_spoofedLeftEntriesAreIgnored() {
        assertThat(ClientAddressForwardingInterceptor.clientAddress(from("172.20.0.3", "1.2.3.4, 203.0.113.50")))
                .isEqualTo("203.0.113.50");
    }

    @Test
    void directFromAPublicAddress_forwardedForIsNotBelieved() {
        assertThat(ClientAddressForwardingInterceptor.clientAddress(from("198.51.100.8", "1.2.3.4")))
                .isEqualTo("198.51.100.8");
    }

    @Test
    void noForwardedFor_usesThePeer() {
        assertThat(ClientAddressForwardingInterceptor.clientAddress(from("172.20.0.3", null))).isEqualTo("172.20.0.3");
    }
}
