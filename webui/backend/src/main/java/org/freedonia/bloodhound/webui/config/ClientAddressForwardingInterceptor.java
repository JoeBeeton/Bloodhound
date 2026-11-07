package org.freedonia.bloodhound.webui.config;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Tells central-server who the real browser is on every call this service proxies, as a single
 * {@code X-Forwarded-For} value (central-server's server.forward-headers-strategy applies it to
 * getRemoteAddr()). A review found central-server saw this container's own address as the client
 * for every login, password reset and API call, so nothing there could rate-limit per client -
 * the login limiter could only key on email, which let anyone lock any account out.
 *
 * <p>Any incoming {@code X-Forwarded-For} is only believed when the direct peer is a private or
 * loopback address - i.e. the Caddy reverse proxy in front of this service on the Docker network
 * (Caddy discards client-supplied X-Forwarded-For and sets its own) - and only its rightmost
 * entry, the one that proxy itself appended. A request reaching this service directly from the
 * internet can't choose the address central-server sees.
 */
public class ClientAddressForwardingInterceptor implements ClientHttpRequestInterceptor {

    static final String HEADER = "X-Forwarded-For";

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            String clientAddress = clientAddress(attributes.getRequest());
            if (clientAddress != null) {
                request.getHeaders().set(HEADER, clientAddress);
            }
        }
        return execution.execute(request, body);
    }

    static String clientAddress(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        String forwardedFor = request.getHeader(HEADER);
        if (forwardedFor != null && !forwardedFor.isBlank() && isInternal(peer)) {
            String[] hops = forwardedFor.split(",");
            String last = hops[hops.length - 1].trim();
            if (!last.isEmpty()) {
                return last;
            }
        }
        return peer;
    }

    private static boolean isInternal(String address) {
        if (address == null) {
            return false;
        }
        try {
            // Literal-only: getByName on an IP literal never does a DNS lookup.
            InetAddress inet = InetAddress.getByName(address);
            return inet.isLoopbackAddress() || inet.isSiteLocalAddress() || isUniqueLocalV6(inet);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean isUniqueLocalV6(InetAddress inet) {
        byte[] bytes = inet.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
