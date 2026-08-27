package org.freedonia.bloodhound.common.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SafeHttpGetTest {

    @SuppressWarnings("unchecked")
    private HttpResponse<String> response(int status, Map<String, List<String>> headers) {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(java.net.http.HttpHeaders.of(headers, (a, b) -> true));
        return response;
    }

    @Test
    void nonRedirectResponse_returnedDirectly_noSecondRequest() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> ok = response(200, Map.of());
        doReturn(ok).when(client).send(any(HttpRequest.class), any());

        HttpResponse<String> result = SafeHttpGet.get(
                client, "https://8.8.8.8/page", Duration.ofSeconds(5), "test-agent", HttpResponse.BodyHandlers.ofString(), 5);

        assertEquals(200, result.statusCode());
    }

    @Test
    void redirectResponse_followsToLocation_revalidatingTheNewHost() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> redirect = response(302, Map.of("location", List.of("https://1.1.1.1/final")));
        HttpResponse<String> finalResponse = response(200, Map.of());
        doReturn(redirect, finalResponse).when(client).send(any(HttpRequest.class), any());

        HttpResponse<String> result = SafeHttpGet.get(
                client, "https://8.8.8.8/start", Duration.ofSeconds(5), "test-agent", HttpResponse.BodyHandlers.ofString(), 5);

        assertEquals(200, result.statusCode());
    }

    @Test
    void redirectToUnsafeHost_refusesToFollow() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> redirect = response(302, Map.of("location", List.of("http://127.0.0.1/internal")));
        doReturn(redirect).when(client).send(any(HttpRequest.class), any());

        IOException e = assertThrows(
                IOException.class,
                () -> SafeHttpGet.get(
                        client,
                        "https://8.8.8.8/start",
                        Duration.ofSeconds(5),
                        "test-agent",
                        HttpResponse.BodyHandlers.ofString(),
                        5));
        assertTrue(e.getMessage().contains("private/loopback/reserved"));
    }

    @Test
    void unsafeHostOnFirstRequest_neverSendsAnything() {
        HttpClient client = mock(HttpClient.class);

        assertThrows(
                IOException.class,
                () -> SafeHttpGet.get(
                        client,
                        "http://169.254.169.254/latest/meta-data/",
                        Duration.ofSeconds(5),
                        "test-agent",
                        HttpResponse.BodyHandlers.ofString(),
                        5));
    }

    @Test
    void redirectWithNoLocationHeader_returnsTheRedirectResponseAsIs() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> redirectNoLocation = response(302, Map.of());
        doReturn(redirectNoLocation).when(client).send(any(HttpRequest.class), any());

        HttpResponse<String> result = SafeHttpGet.get(
                client, "https://8.8.8.8/start", Duration.ofSeconds(5), "test-agent", HttpResponse.BodyHandlers.ofString(), 5);

        assertEquals(302, result.statusCode());
    }

    @Test
    void exceedsMaxRedirects_throws() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> alwaysRedirects = response(302, Map.of("location", List.of("https://8.8.8.8/loop")));
        doReturn(alwaysRedirects).when(client).send(any(HttpRequest.class), any());

        assertThrows(
                IOException.class,
                () -> SafeHttpGet.get(
                        client,
                        "https://8.8.8.8/start",
                        Duration.ofSeconds(5),
                        "test-agent",
                        HttpResponse.BodyHandlers.ofString(),
                        2));
    }

    @Test
    void getWithRedirectChainHeaders_unionsHeadersFromEveryHop_laterHopWinsOnConflict() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> redirect =
                response(301, Map.of("location", List.of("https://1.1.1.1/final"), "x-redirect-by", List.of("WordPress")));
        HttpResponse<String> finalResponse = response(200, Map.of("x-final-only", List.of("yes")));
        doReturn(redirect, finalResponse).when(client).send(any(HttpRequest.class), any());

        SafeHttpGet.RedirectChainResult<String> result = SafeHttpGet.getWithRedirectChainHeaders(
                client, "https://8.8.8.8/start", Duration.ofSeconds(5), "test-agent", HttpResponse.BodyHandlers.ofString(), 5);

        assertEquals(200, result.response().statusCode());
        assertEquals("WordPress", result.allHopHeaders().get("x-redirect-by"));
        assertEquals("yes", result.allHopHeaders().get("x-final-only"));
    }
}
